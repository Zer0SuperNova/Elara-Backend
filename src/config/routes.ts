export const Routes: Record<string, string> = {
    EK4JD4: "/api/v1/handshake/init",
    Z9Q1TT: "/api/v1/handshake/finalize",
    M5N8LS: "/api/v1/hit",
    A7UP42: "/api/v1/security/alert/upload"
};

export const ActionRoutes: Record<string, string> = {

    // test
    echo: "/api/v1/echo",

    // models
    getModelToken: "/api/v1/model/token",
    streamModel: "/api/v1/model/stream",

    // auth
    login: "/api/v1/login",
    heartbeat: "/api/v1/heartbeat",
    resumeSession: "/api/v1/session",

    // products
    getProducts: "/api/v1/products",

    // check product access (for heartbeat)
    checkProductAccess: "/api/v1/product/check",

    // licenses
    getLicenses: "/api/v1/licenses",
    activateLicense: "/api/v1/licenses/activate",
    checkLicense: "/api/v1/license/check",

    // cdn
    getCdnAsset: "/api/v1/cdn",

    // builds
    requestBuild: "/api/v1/build/request",
    getBuildKey: "/api/v1/build/key",
    downloadBuild: "/api/v1/build/download",

    // security
    ban: "/api/v1/security/ban",
    securityAlertInit: "/api/v1/security/alert/init",

    // diagnostics / watchdog
    //diagnostics: "/api/v1/diagnostics",

};
