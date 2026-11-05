                                                                                                           

                                     
                          
                     
                                   
                         
                 
                                
 

/**
 * Deterministically analyzes HTTP response status, headers, and body tokens for anti-bot challenges.
 */
export function detectChallenge(
  statusCode        ,
  headers                                    ,
  bodyText         
)                     {
  const normHeaders                         = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v !== undefined) {
      normHeaders[k.toLowerCase()] = v.toLowerCase();
    }
  }

  const evidence           = [];
  const body = (bodyText ?? "").toLowerCase();

  // 1. Cloudflare Detection
  const cfMitigated = normHeaders["cf-mitigated"];
  const cfRay = normHeaders["cf-ray"] || normHeaders["cf-ray-id"];
  const server = normHeaders["server"] ?? "";
  const isCloudflareServer = server.includes("cloudflare");

  if (cfMitigated === "challenge" || body.includes("__cf_chl_opt") || body.includes("cloudflare ray id:")) {
    evidence.push("Cloudflare Turnstile / Challenge Interstitial detected");
    return {
      vendor: "cloudflare",
      isBlocked: statusCode === 403 || statusCode === 429 || statusCode === 503,
      isChallengeInterstitial: true,
      retryAfterSec: parseRetryAfter(normHeaders["retry-after"]),
      rayId: cfRay,
      fingerprintEvidence: evidence,
    };
  }

  // 2. DataDome Detection
  if (normHeaders["x-datadome"] || body.includes("captcha-delivery.com") || body.includes("datadome")) {
    evidence.push("DataDome protection payload identified");
    return {
      vendor: "datadome",
      isBlocked: statusCode === 403 || statusCode === 429,
      isChallengeInterstitial: true,
      retryAfterSec: parseRetryAfter(normHeaders["retry-after"]),
      fingerprintEvidence: evidence,
    };
  }

  // 3. PerimeterX Detection
  if (body.includes("_pxcaptcha") || body.includes("perimeterx") || normHeaders["x-px-block"]) {
    evidence.push("PerimeterX captcha challenge page identified");
    return {
      vendor: "perimeterx",
      isBlocked: statusCode === 403,
      isChallengeInterstitial: true,
      fingerprintEvidence: evidence,
    };
  }

  // 4. Akamai Detection
  if (normHeaders["x-akamai-transformed"] && (statusCode === 403 || statusCode === 429)) {
    evidence.push("Akamai Ghost Bot Manager barrier identified");
    return {
      vendor: "akamai",
      isBlocked: true,
      isChallengeInterstitial: true,
      retryAfterSec: parseRetryAfter(normHeaders["retry-after"]),
      fingerprintEvidence: evidence,
    };
  }

  // 5. Generic HTTP 429 / 403
  if (statusCode === 429 || (statusCode === 403 && (isCloudflareServer || body.includes("access denied")))) {
    evidence.push("Generic WAF throttle or access prohibition");
    return {
      vendor: isCloudflareServer ? "cloudflare" : "generic-waf",
      isBlocked: true,
      isChallengeInterstitial: false,
      retryAfterSec: parseRetryAfter(normHeaders["retry-after"]),
      rayId: cfRay,
      fingerprintEvidence: evidence,
    };
  }

  return {
    vendor: "none",
    isBlocked: false,
    isChallengeInterstitial: false,
    fingerprintEvidence: [],
  };
}

function parseRetryAfter(headerValue         )                     {
  if (!headerValue) return undefined;
  const parsed = parseInt(headerValue, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}
