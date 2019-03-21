import { Request, Response } from "@opennetwork/http-representation";
export declare type WebAccessControlResultObject = {
    public: boolean;
};
export declare type WebAccessControlResult = false | WebAccessControlResultObject;
export declare type WebAccessControlOptions = {
    agent: string;
    origin: string;
    fetch: (request: Request) => Promise<Response>;
    trustedOrigins?: string[];
    allowedCache?: {
        [key: string]: WebAccessControlResult;
    };
    aclResourceCache?: {
        [key: string]: Promise<string>;
    };
    aclSuffix?: string;
};
export declare type WebAccessControlMode = "Read" | "Write" | "Control" | string;
export declare function isAllowed(resource: string, mode: WebAccessControlMode, options: WebAccessControlOptions): Promise<WebAccessControlResult>;
/**
 * Will return a response if ACL disallows the agent to access the resource, or returns undefined if allowed
 * @param resource
 * @param mode
 * @param options
 */
export declare function getResponse(resource: string, mode: WebAccessControlMode, options: WebAccessControlOptions): Promise<Response | undefined>;
