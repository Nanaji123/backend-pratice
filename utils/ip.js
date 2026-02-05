export const getClientIp = (req) => {
    const cfIp = req.headers["cf-connecting-ip"];
    if (cfIp) return cfIp;

    const xForwardedFor = req.headers["x-forwarded-for"];
    if (xForwardedFor) {
        return xForwardedFor.split(",")[0].trim();
    }

    const ip =
        req.headers["x-real-ip"] ||
        req.ip ||
        req.connection?.remoteAddress;

    return ip?.replace(/^::ffff:/, "") || "unknown";
};
