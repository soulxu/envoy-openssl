#include "source/extensions/transport_sockets/tls/ssl_handshaker.h"

#include "envoy/stats/scope.h"

#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/http/headers.h"
#include "source/common/runtime/runtime_features.h"
#include "source/extensions/transport_sockets/tls/utility.h"

#include <ext/openssl/ssl.h>

using Envoy::Network::PostIoAction;

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

void ValidateResultCallbackImpl::onSslHandshakeCancelled() { extended_socket_info_.reset(); }

void ValidateResultCallbackImpl::onCertValidationResult(bool succeeded,
                                                        Ssl::ClientValidationStatus detailed_status,
                                                        const std::string& /*error_details*/,
                                                        uint8_t tls_alert) {
  if (!extended_socket_info_.has_value()) {
    return;
  }
  extended_socket_info_->setCertificateValidationStatus(detailed_status);
  extended_socket_info_->setCertificateValidationAlert(tls_alert);
  extended_socket_info_->onCertificateValidationCompleted(succeeded, true);
}

SslExtendedSocketInfoImpl::~SslExtendedSocketInfoImpl() {
  if (cert_validate_result_callback_.has_value()) {
    cert_validate_result_callback_->onSslHandshakeCancelled();
  }
}

void SslExtendedSocketInfoImpl::setCertificateValidationStatus(
    Envoy::Ssl::ClientValidationStatus validated) {
  certificate_validation_status_ = validated;
}

Envoy::Ssl::ClientValidationStatus SslExtendedSocketInfoImpl::certificateValidationStatus() const {
  return certificate_validation_status_;
}

void SslExtendedSocketInfoImpl::onCertificateValidationCompleted(bool succeeded, bool async) {
  cert_validation_result_ =
      succeeded ? Ssl::ValidateStatus::Successful : Ssl::ValidateStatus::Failed;
  if (cert_validate_result_callback_.has_value()) {
    cert_validate_result_callback_.reset();
    // Resume handshake.
    if (async) {
      ssl_handshaker_.handshakeCallbacks()->onAsynchronousCertValidationComplete();
    }
  }
}

Ssl::ValidateResultCallbackPtr SslExtendedSocketInfoImpl::createValidateResultCallback() {
  auto callback = std::make_unique<ValidateResultCallbackImpl>(
      ssl_handshaker_.handshakeCallbacks()->connection().dispatcher(), *this);
  cert_validate_result_callback_ = *callback;
  cert_validation_result_ = Ssl::ValidateStatus::Pending;
  return callback;
}

SslHandshakerImpl::SslHandshakerImpl(bssl::UniquePtr<SSL> ssl, int ssl_extended_socket_info_index,
                                     Ssl::HandshakeCallbacks* handshake_callbacks)
    : ssl_(std::move(ssl)), handshake_callbacks_(handshake_callbacks),
      extended_socket_info_(*this) {
  SSL_set_ex_data(ssl_.get(), ssl_extended_socket_info_index, &(this->extended_socket_info_));
}

bool SslHandshakerImpl::peerCertificateValidated() const {
  return extended_socket_info_.certificateValidationStatus() ==
         Envoy::Ssl::ClientValidationStatus::Validated;
}

Network::PostIoAction SslHandshakerImpl::doHandshake() {
  ASSERT(state_ != Ssl::SocketState::HandshakeComplete && state_ != Ssl::SocketState::ShutdownSent);

  //ENVOY_LOG_MISC(debug, "###### {}", ossl_SSL_get_mode(ssl()));

  int rc = SSL_do_handshake(ssl());
  if (rc == 1) {
    state_ = Ssl::SocketState::HandshakeComplete;
    handshake_callbacks_->onSuccess(ssl());

    // It's possible that we closed during the handshake callback.
    return handshake_callbacks_->connection().state() == Network::Connection::State::Open
               ? PostIoAction::KeepOpen
               : PostIoAction::Close;
  } else {
    ossl_OSSL_ASYNC_FD* fds;
    size_t numfds;
    int err = SSL_get_error(ssl(), rc);
    //ENVOY_CONN_LOG(trace, "ssl error occurred while read: {}", handshake_callbacks_->connection(),
    //               Utility::getErrorDescription(err));
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return PostIoAction::KeepOpen;
    // case SSL_ERROR_WANT_PRIVATE_KEY_OPERATION:
    // case SSL_ERROR_WANT_CERTIFICATE_VERIFY:
    //   state_ = Ssl::SocketState::HandshakeInProgress;
    //   return PostIoAction::KeepOpen;
    case ossl_SSL_ERROR_WANT_ASYNC:
      ENVOY_CONN_LOG(debug, "SSL handshake: request async handling", handshake_callbacks_->connection());

      if (state_ == Ssl::SocketState::HandshakeInProgress) {
        return PostIoAction::KeepOpen;
      }

      state_ = Ssl::SocketState::HandshakeInProgress;

      rc = ossl_SSL_get_all_async_fds(ssl_.get(), NULL, &numfds);
      if (rc == 0) {
        handshake_callbacks_->onFailure();
        return PostIoAction::Close;
      }

      /* We only wait for the first fd here! Will fail if multiple async engines. */
      if (numfds != 1) {
        ENVOY_LOG(error, "Only one async OpenSSL engine is supported currently");
        handshake_callbacks_->onFailure();
        return PostIoAction::Close;
      }

      fds = static_cast<ossl_OSSL_ASYNC_FD*>(malloc(numfds * sizeof(ossl_OSSL_ASYNC_FD)));
      if (fds == NULL) {
        handshake_callbacks_->onFailure();
        return PostIoAction::Close;
      }

      rc = ossl_SSL_get_all_async_fds(ssl_.get(), fds, &numfds);
      if (rc == 0) {
        free(fds);
        handshake_callbacks_->onFailure();
        return PostIoAction::Close;
      }

      file_event_ = handshake_callbacks_->connection().dispatcher().createFileEvent(
          fds[0], [this](uint32_t /* events */) -> void { asyncCb(); },
          Event::FileTriggerType::Edge, Event::FileReadyType::Read);
      ENVOY_CONN_LOG(debug, "SSL async fd: {}, numfds: {}", handshake_callbacks_->connection(), fds[0],
                     numfds);
      free(fds);
      return PostIoAction::KeepOpen;
    default:
      handshake_callbacks_->onFailure();
      return PostIoAction::Close;
    }
  }
}

void SslHandshakerImpl::asyncCb() {
  ENVOY_CONN_LOG(debug, "SSL async done!", handshake_callbacks_->connection());

  ASSERT(state_ != Ssl::SocketState::HandshakeComplete);
  // We lose the return value here, so might consider propagating it with an event
  // in case we run into "Close" result from the handshake handler.
  PostIoAction action = doHandshake();
  if (action == PostIoAction::Close) {
    ENVOY_CONN_LOG(debug, "async handshake completion error", handshake_callbacks_->connection());
    handshake_callbacks_->onFailure();
    handshake_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
  }
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
