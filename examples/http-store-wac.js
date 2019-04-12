import { FSStore } from "@opennetwork/http-store";
import { fromRequest, sendResponse } from "@opennetwork/http-representation-node";
import { Response } from "@opennetwork/http-representation";
import { getResponse, getAllowedHeaderValue } from "../dist";
import http from "http";
import fs from "fs";
import rimraf from "rimraf";
import { mkdirp } from "fs-extra";
import withACL from "./util/http-store-with-acl";
import ACLCheck from "@solid/acl-check";

ACLCheck.configureLogger(() => {});

const store = withACL(new FSStore({
  fs,
  rootPath: './examples/store',
  statusCodes: http.STATUS_CODES,
  rimraf,
  mkdirp
}));

const port = 8080;

const origin = `http://localhost:${port}/`;

async function handle(initialRequest, initialResponse) {
  const request = fromRequest(initialRequest, origin);

  // export type WebAccessControlMode = "Read" | "Write" | "Append" | "Control" | string;
  const mode = {
    HEAD: 'Read',
    GET: 'Read',
    DELETE: 'Write',
    PUT: 'Write',
    POST: 'Write', // FS Store doesn't support post, but allow it here
    COPY: true,
    OPTIONS: 'Read'
  }[request.method.toUpperCase()];

  if (!mode) {
    // We can't handle this method using WAC
    return sendResponse(
      new Response(null, {
        status: 405
      }),
      initialRequest,
      initialResponse
    );
  }

  const options = {
    agent: 'http://localhost:8080/public#self',
    origin,
    fetch: store.fetch,
    trustedOrigins: [origin],
    // allowedCache: {},
    // aclResourceCache: {},
    // fetchCache: {},
    getAccessResourceAndModeIfACLResource: resource => /\.acl$/i.test(resource) ? ({
      resource: resource.replace(/\.acl$/i, ''),
      mode: 'Control'
    }) : null
  };

  const allowValue = await getAllowedHeaderValue(request.url, options);

  console.log({ allowValue });

  // Skip if true, as COPY will also hit the "GET" & "PUT"
  const earlyResponse = await getResponse(
    request.url,
    mode,
    options
  );

  console.log({ earlyResponse });

  if (earlyResponse) {
    earlyResponse.headers.set("WAC-Allow", allowValue);
    return sendResponse(earlyResponse, initialRequest, initialResponse);
  }

  // Anything past here is authenticated for said access
  const fetchedResponse = await store.fetch(
    request
  );

  console.log({ fetchedResponse });

  fetchedResponse.headers.set("WAC-Allow", allowValue);

  return sendResponse(fetchedResponse, initialRequest, initialResponse)
}

const server = http.createServer((request, response) => {
  return handle(request, response)
    .catch(error => {
      console.error(error);
      try {
        response.writeHead(500, {
          "Content-Type": "text/plain"
        });
        response.end(error.message);
      } catch(e) {
        // Unsure what to do here, this would have only been if
        // the head was already written
      }
    });
});


server.listen(port, () => console.log(`Listening on port ${port}`));
