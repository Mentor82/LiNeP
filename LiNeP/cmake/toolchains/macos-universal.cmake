# macOS Universal Binary (Intel + Apple Silicon in one .dylib)
# Requires Xcode 12+ and macOS 11+ SDK.
set(CMAKE_SYSTEM_NAME  Darwin)
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")
