"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const http_representation_1 = require("@opennetwork/http-representation");
const rdflib_1 = __importDefault(require("rdflib"));
const acl_check_1 = __importDefault(require("@solid/acl-check/src/acl-check"));
const NAMESPACE_ACL = rdflib_1.default.Namespace("http://www.w3.org/ns/auth/acl#");
function resolveValue(value) {
    return __awaiter(this, void 0, void 0, function* () {
        return value;
    });
}
function createForbiddenResponse() {
    return new http_representation_1.Response(undefined, {
        status: 403,
        statusText: "Forbidden"
    });
}
function createUnauthorizedResponse() {
    return new http_representation_1.Response(undefined, {
        status: 401,
        statusText: "Unauthorized"
    });
}
function createErrorResponse(error) {
    return new http_representation_1.Response(typeof error === "string" ? error : error.message, {
        status: 500,
        statusText: "Internal Server Error"
    });
}
function getContainerForResource(resource) {
    const url = new URL(resource);
    if (url.pathname === "/") {
        return undefined;
    }
    const reduce = () => {
        url.pathname = url.pathname.substr(0, url.pathname.lastIndexOf("/"));
    };
    if (url.pathname.endsWith("/")) {
        reduce();
    }
    reduce();
    return url.toString();
}
function getACLLinkFromResponse(response) {
    const links = response.headers.getAll("Link");
    return undefined;
}
function getACLResource(resource, options) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield options.fetch(new http_representation_1.Request(resource, {
            method: "HEAD"
        }));
        return getACLLinkFromResponse(response);
    });
}
function getCached(cache, fn, key, ...args) {
    return __awaiter(this, void 0, void 0, function* () {
        if (cache[key]) {
            return cache[key];
        }
        cache[key] = fn(key, ...args);
        return cache[key];
    });
}
function getACL(resource, options) {
    return __awaiter(this, void 0, void 0, function* () {
        const aclResource = yield getCached(options.aclResourceCache, getACLResource, resource, options);
        const request = new http_representation_1.Request(aclResource, {
            method: "GET",
            headers: {
                "Accept": "text/turtle"
            }
        });
        const response = yield options.fetch(request);
        if (response.status === 404) {
            return getACL(getContainerForResource(resource), options);
        }
        if (!response.ok) {
            throw new Error("Could not retrieve ACL");
        }
        const body = yield response.text();
        const graph = rdflib_1.default.graph();
        yield new Promise((resolve, reject) => rdflib_1.default.parse(body, graph, resource, request.headers.get("Accept"), (error) => error ? reject(error) : resolve()));
        return {
            graph,
            aclResource,
            resource
        };
    });
}
function getOrigin(options) {
    return __awaiter(this, void 0, void 0, function* () {
        const agentOrigin = options.origin;
        if (!options.isOriginAllowed) {
            return agentOrigin;
        }
        const allowed = resolveValue(options.isOriginAllowed(agentOrigin));
        return allowed ? agentOrigin : undefined;
    });
}
function isAllowed(resource, mode, options) {
    return __awaiter(this, void 0, void 0, function* () {
        const { allowedCache, agent } = options, cacheKey = `${mode}:${resource}:${agent || "---ANONYMOUS---"}`;
        if (allowedCache && (allowedCache[cacheKey] || allowedCache[cacheKey] === false)) {
            return allowedCache[cacheKey];
        }
        const acl = yield getACL(resource, options);
        if (!acl) {
            if (allowedCache) {
                allowedCache[cacheKey] = false;
            }
            return false;
        }
        const agentOrigin = yield getOrigin(options);
        const modes = [mode];
        let workingResource = resource;
        const aclSuffix = options.aclSuffix || ".acl";
        if (resource.endsWith(aclSuffix)) {
            modes.push("Control");
            workingResource = workingResource.substr(0, workingResource.length - aclSuffix.length);
        }
        const originTrustedModes = yield Promise.resolve()
            // Because of https://github.com/solid/acl-check/issues/23
            .then(() => acl_check_1.default.getTrustedModesForOrigin());
        return undefined;
    });
}
exports.isAllowed = isAllowed;
/**
 * Will return a response if ACL disallows the agent to access the resource, or returns undefined if allowed
 * @param resource
 * @param mode
 * @param options
 */
function getResponse(resource, mode, options) {
    return isAllowed(resource, mode, options)
        .then(allowed => {
        if (allowed) {
            return undefined;
        }
        if (options.agent) {
            return createForbiddenResponse();
        }
        else {
            return createUnauthorizedResponse();
        }
    })
        .catch(error => createErrorResponse(error));
}
exports.getResponse = getResponse;
//# sourceMappingURL=index.js.map