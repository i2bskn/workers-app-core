import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

// Revokes every OAuth grant of the user, with their tokens. Errors propagate (500); running it
// again revokes what is left. KV is eventually consistent, so a grant created in another location
// within about 60 seconds may not be listed yet.
export async function revokeAllGrants(oauth: OAuthHelpers, userId: string): Promise<void> {
  let cursor: string | undefined;
  do {
    const page = await oauth.listUserGrants(userId, cursor === undefined ? undefined : { cursor });
    await Promise.all(page.items.map((grant) => oauth.revokeGrant(grant.id, userId)));
    cursor = page.cursor;
  } while (cursor);
}

export type McpClient = { clientId: string; clientName: string };

// The OAuth clients that the user has authorized, each once, in the order of the grants. A client that cannot be
// looked up (deleted, or a CIMD document that cannot be fetched) is named by its client ID. KV is eventually
// consistent, so a client authorized within about 60 seconds may not be listed yet.
export async function listUserClients(oauth: OAuthHelpers, userId: string): Promise<McpClient[]> {
  const clientIds: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await oauth.listUserGrants(userId, cursor === undefined ? undefined : { cursor });
    for (const grant of page.items) if (!clientIds.includes(grant.clientId)) clientIds.push(grant.clientId);
    cursor = page.cursor;
  } while (cursor);
  return Promise.all(clientIds.map(async (clientId) => ({ clientId, clientName: await clientName(oauth, clientId) })));
}

// The client_name of a client, or the client ID when it cannot be looked up.
export async function clientName(oauth: OAuthHelpers, clientId: string): Promise<string> {
  try {
    const client = await oauth.lookupClient(clientId);
    const name = client?.clientName?.trim();
    return name === undefined || name === "" ? clientId : name;
  } catch {
    return clientId;
  }
}
