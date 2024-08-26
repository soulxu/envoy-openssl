find_package(OpenSSL 3.0 COMPONENTS Crypto SSL)

if(OpenSSL_FOUND)
    add_custom_target(OpenSSL)
    get_filename_component(OPENSSL_LIBRARY_DIR ${OPENSSL_CRYPTO_LIBRARY} DIRECTORY)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION} (${OPENSSL_LIBRARY_DIR})")
else()
    message(STATUS "Building OpenSSL (${OPENSSL_URL})")
    include(ExternalProject)
    set(OPENSSL_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl/source)
    set(OPENSSL_CONFIG_CMD ${OPENSSL_SOURCE_DIR}/config)
    set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl/install)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
    set(OPENSSL_LIBRARY_DIR ${OPENSSL_INSTALL_DIR}/lib)
    set (ENV{http_proxy} http://child-prc.intel.com:912)
    set (ENV{https_proxy} http://child-prc.intel.com:912)
    ExternalProject_Add(OpenSSL
        SOURCE_DIR ${OPENSSL_SOURCE_DIR}
        DOWNLOAD_COMMAND curl -o ${CMAKE_CURRENT_BINARY_DIR}/openssl/openssl-3.0.13.tar.gz -L -x "http://child-prc.intel.com:912" "https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.13.tar.gz" && tar -xzvf ${CMAKE_CURRENT_BINARY_DIR}/openssl/openssl-3.0.13.tar.gz --strip-components=1 -C ${CMAKE_CURRENT_BINARY_DIR}/openssl/source
        CONFIGURE_COMMAND ${OPENSSL_CONFIG_CMD} --prefix=${OPENSSL_INSTALL_DIR} --libdir=lib -DOPENSSL_INIT_DEBUG
        TEST_COMMAND ""
        INSTALL_COMMAND make install_sw
        # LOG_DOWNLOAD ON
    )
endif()
