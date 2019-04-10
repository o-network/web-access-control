import { Request, Response } from "@opennetwork/http-representation";
import $rdf, { IndexedFormula, NamedNode } from "rdflib";
import ACLCheck from "@solid/acl-check";
import join from "join-path";

const NAMESPACE_ACL = $rdf.Namespace("http://www.w3.org/ns/auth/acl#");

export type WebAccessControlResultObject = {
  public: boolean;
};

export type WebAccessControlResult = false | WebAccessControlResultObject;

export type WebAccessControlResourceAndMode = {
  resource: string,
  mode: WebAccessControlMode | WebAccessControlMode[]
};

export type WebAccessControlGetGraph = (url: string, graph: IndexedFormula) => Promise<Response | IndexedFormula>;

export type WebAccessControlOptions = {
  agent: string;
  origin: string;
  fetch: (request: Request) => Promise<Response>;
  trustedOrigins?: string[]
  allowedCache?: { [key: string]: WebAccessControlResult };
  aclResourceCache?: { [key: string]: Promise<string> };
  getAccessResourceAndModeIfACLResource?: (resource: string) => WebAccessControlResourceAndMode | Promise<WebAccessControlResourceAndMode>
  getGraph?: WebAccessControlGetGraph
};

export type WebAccessControlMode = "Read" | "Write" | "Append" | "Control" | string;

type ACLDetails = {
  graph: IndexedFormula;
  aclResource: string;
  resource: string;
};

function createForbiddenResponse() {
  return new Response(undefined, {
    status: 403,
    statusText: "Forbidden"
  });
}

function createUnauthorizedResponse() {
  return new Response(undefined, {
    status: 401,
    statusText: "Unauthorized"
  });
}

function createErrorResponse(error: string | Error) {
  return new Response(typeof error === "string" ? error : error.message, {
    status: 500,
    statusText: "Internal Server Error"
  });
}

function getContainerForResource(resource: string): string | undefined {
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

function getACLLinkFromResponse(response: Response): string | undefined {
  /*
    https://tools.ietf.org/html/rfc8288

     Link       = #link-value
     link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
     link-param = token BWS [ "=" BWS ( token / quoted-string ) ]

     OWS = Optional whitespace
     BWS = Bad whitespace AKA whitespace _should_ not be present

     Should look like `Link: <.acl>; rel="acl"
   */
  const links = response.headers.getAll("Link");
  const foundPart = links
    .map(link => link
      .split(";")
      .map(value => value.trim())
      .filter(value => value)
    )
    .filter(parts => parts.length >= 2)
    .map(parts => {
      if (!/^<.+>$/.test(parts[0])) {
        return undefined;
      }
      const foundRel = parts.find(
        part => /rel\s?=\s?"?acl"?/.test(part)
      );
      if (!foundRel) {
        return;
      }
      // Already verified to be in correct format
      return parts[0];
    })
    .find(value => !!value);
  if (!foundPart) {
    return undefined;
  }
  return foundPart.substr(0, foundPart.length - 1).substr(1);
}


async function getACLResource(resource: string, options: WebAccessControlOptions): Promise<string | undefined> {
  const response = await options.fetch(new Request(resource, {
    method: "HEAD"
  }));
  const link = getACLLinkFromResponse(response);
  if (!link) {
    return undefined;
  }
  const resourceUrl = new URL(resource);
  resourceUrl.pathname = join(
    resourceUrl.pathname.endsWith("/") ? resourceUrl.pathname : resourceUrl.pathname.substr(0, resourceUrl.pathname.lastIndexOf("/")),
    link
  );
  return resourceUrl.toString();
}

async function getCached<T>(cache: { [key: string]: Promise<T> } | undefined, fn: (key: string, ...args: any[]) => Promise<T>, key: string, ...args: any[]): Promise<T> {
  if (cache && cache[key]) {
    return cache[key];
  }
  // This is cached no matter what the result is
  const result = fn(key, ...args);
  if (!cache) {
    return result;
  }
  cache[key] = result;
  // If we run into an error, reset the cache so we
  // can see if there is a non error'd version
  result
    .catch(() => {
      if (cache[key] === result) {
        cache[key] = undefined;
      }
    });
  return result;
}

async function getACL(resource: string, getGraph: WebAccessControlGetGraph, options: WebAccessControlOptions): Promise<ACLDetails | undefined> {
  const aclResource = await getCached(options.aclResourceCache, getACLResource, resource, options);

  function getContainerACL() {
    return getACL(
      getContainerForResource(resource),
      getGraph,
      options
    );
  }

  // No link was found for the resource
  if (!aclResource) {
    return getContainerACL();
  }

  const graph = $rdf.graph();
  const result: Response | IndexedFormula = await getGraph(aclResource, graph);

  if (result instanceof Response && result.status === 404) {
    return getContainerACL();
  }

  if (result instanceof Response && !result.ok) {
    throw new Error("Could not retrieve ACL");
  }

  return {
    graph,
    aclResource,
    resource
  };
}

export async function isAllowed(resource: string, mode: WebAccessControlMode | WebAccessControlMode[], options: WebAccessControlOptions): Promise<WebAccessControlResult> {
  const { allowedCache, agent } = options,
    cacheKey = `${mode}:${resource}:${agent || "---ANONYMOUS---"}`;

  if (allowedCache && (allowedCache[cacheKey] || allowedCache[cacheKey] === false)) {
    return allowedCache[cacheKey];
  }

  const getGraph: WebAccessControlGetGraph = options.getGraph || (async (url: string, graph: IndexedFormula) => {
    const request = new Request(
      url,
      {
        method: "GET",
        headers: {
          "Accept": "text/turtle"
        }
      }
    );
    const response = await options.fetch(request);
    if (!response.ok) {
      return response;
    }
    const body = await response.text();
    await new Promise(
      (resolve, reject) => $rdf.parse(
        body,
        graph,
        resource,
        request.headers.get("Accept"),
        (error) => error ? reject(error) : resolve()
      )
    );
    return graph;
  });

  const acl = await getACL(resource, getGraph, options);

  if (!acl) {
    if (allowedCache) {
      allowedCache[cacheKey] = false;
    }
    return false;
  }

  const agentOrigin = options.origin;

  let modes = mode;
  let workingResource = resource;

  if (options.getAccessResourceAndModeIfACLResource) {
    const newDetails = await Promise.resolve(options.getAccessResourceAndModeIfACLResource(workingResource));
    if (newDetails) {
      workingResource = newDetails.resource;
      modes = newDetails.mode;
    }
  }

  modes = Array.isArray(modes) ? [...modes] : [modes];

  const originTrustedModes = await Promise.resolve()
  // Because of https://github.com/solid/acl-check/issues/23
    .then(() => ACLCheck.getTrustedModesForOrigin(
      acl.graph,
      $rdf.sym(workingResource),
      workingResource.endsWith("/"),
      $rdf.sym(acl.aclResource),
      agentOrigin,
      async (uriNode: NamedNode): Promise<IndexedFormula> => {
        const value = await getGraph(uriNode.doc().value, acl.graph);
        if (value instanceof Response && !value.ok) {
          throw new Error(`Could not fetch: ${uriNode.doc().value}`);
        }
        return value as IndexedFormula;
      }
    ));

  const denied = ACLCheck.accessDenied(
    acl.graph,
    $rdf.sym(workingResource),
    workingResource.endsWith("/"),
    $rdf.sym(acl.aclResource),
    agent ? $rdf.sym(agent) : undefined,
    modes.map(mode => NAMESPACE_ACL(mode)),
    agentOrigin ? $rdf.sym(agentOrigin) : undefined,
    options.trustedOrigins ? options.trustedOrigins.map(origin => $rdf.sym(origin)) : undefined,
    originTrustedModes
  );

  const result = denied ? false : {
    public: !options.agent
  };

  if (allowedCache) {
    allowedCache[cacheKey] = result;
  }

  return result;
}

/**
 * Will return a response if ACL disallows the agent to access the resource, or returns undefined if allowed
 * @param resource
 * @param mode
 * @param options
 */
export function getResponse(resource: string, mode: WebAccessControlMode | WebAccessControlMode[], options: WebAccessControlOptions): Promise<Response | undefined> {
  return isAllowed(resource, mode, options)
    .then(allowed => {
      if (allowed) {
        return undefined;
      }
      if (options.agent) {
        return createForbiddenResponse();
      } else {
        return createUnauthorizedResponse();
      }
    })
    .catch(error => createErrorResponse(error));
}
