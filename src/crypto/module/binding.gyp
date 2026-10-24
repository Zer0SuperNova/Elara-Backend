{
  "targets": [{
    "target_name": "cryptomodule",
    "product_dir": "bin",
    "sources": [
      "<!@(find src -name '*.cpp' | grep -v thirdparty)"
    ],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")",
      "src",
      "src/thirdparty/include",
      "/usr/include"
    ],
    "libraries": [
      "-lsodium"
    ],
    "cflags_cc": ["-std=c++20", "-fexceptions"],
    "defines": ["NAPI_CPP_EXCEPTIONS"]
  }]
}