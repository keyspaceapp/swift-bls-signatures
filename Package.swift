// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "swift-bls-signatures",
    products: [
        .library(
            name: "BLS",
            targets: ["BLS"]),
    ],
    targets: [
        .target(
            name: "relic",
            dependencies: [],
            path: "Sources/relic/src",
            exclude: [
                "arch/relic_arch_x86.c",
                "CMakeLists.txt",
                "md/blake2_COPYING",
                "relic_bench.c",
                "relic_conf.c",
                "relic_test.c",
                "rand/relic_rand_rdrnd.c"
            ],
            sources: [
                "relic_core.c",
                "relic_err.c",
                "relic_util.c",
                "arch/relic_arch_none.c",
                "bc",
                "bn",
                "cp",
                "dv",
                "eb",
                "ed",
                "ep",
                "epx",
                "fb",
                "fbx",
                "fp",
                "fpx",
                "low/easy", // not sure about this...
                "md",
                "mpc",
                "pc",
                "pp",
                "rand",
                "tmpl"
            ],
            publicHeadersPath: "./",
            cSettings: [
                .headerSearchPath("tmpl"),
                .headerSearchPath("../include"),
                .headerSearchPath("../include/low"),
                .headerSearchPath("../../relic_conf")
            ]),
        .target(
            name: "bls-signatures",
            dependencies: [
                "relic"
            ],
            path: "Sources/bls-signatures/src",
            exclude: [
                "CMakeLists.txt",
                "test-bench.cpp",
                "test.cpp"
            ],
            sources: [
                "bls.cpp",
                "elements.cpp",
                "privatekey.cpp",
                "schemes.cpp"
            ],
            publicHeadersPath: "./",
            cxxSettings: [
                .headerSearchPath("."),
                .headerSearchPath("../../relic/include"),
                .headerSearchPath("../../relic_conf")
            ]),
        .target(
            name: "ObjCBLS",
            dependencies: [
                "bls-signatures"
            ],
            path: "Sources/ObjCBLS",
            cxxSettings: [
                .headerSearchPath("../bls-signatures/src"),
                .headerSearchPath("../relic_conf"),
                .headerSearchPath("../relic/include")
            ]),
        .target(
            name: "BLS",
            dependencies: ["ObjCBLS"]),
        .testTarget(
            name: "BLSTests",
            dependencies: ["BLS"]),
    ],
    cxxLanguageStandard: .cxx17
)
