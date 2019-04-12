import { dirname, relative } from "path";
import { Request } from "@opennetwork/http-representation";

async function getACLUrl(store, url) {
  if (/\.acl$/i.test(url)) {
    return undefined;
  }
  const aclUrl = `${url}.acl`;
  const headResponse = await store.fetch(
    new Request(
      aclUrl,
      {
        method: "HEAD"
      }
    )
  );
  if (headResponse.ok) {
    return aclUrl;
  }
  // Only return if we have a direct ACL
  return undefined;
  // const instance = new URL(url);
  // if (instance.pathname === "/") {
  //   return undefined;
  // }
  // const dir = dirname(instance.pathname);
  // return getACLUrl(store, new URL(dir, instance.origin))
}

export default function(store) {
  return {
    fetch: async (request) => {
      console.log('Fetching', request.method, request.url);

      const response = await store.fetch(request);

      if (response.ok) {

        const aclUrl = await getACLUrl(store, request.url);

        if (aclUrl) {
          const aclUrlInstance = new URL(aclUrl),
            originalUrlInstance = new URL(request.url);

          response.headers.set("Link", `<${relative(dirname(originalUrlInstance.pathname), aclUrlInstance.pathname)}>; rel="acl"`)
        }

      }

      return response;
    }
  }
};
