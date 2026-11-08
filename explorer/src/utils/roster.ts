import { displayAddress, fromRaddress, isRaddress, parseSwarmRoster } from '@sumchain/sdk';

/**
 * The swarm roster (sum-chain #309 item 3): the accounts this explorer shows in
 * the agent form `r0…`, from `VITE_SWARM_ROSTER` (plain or `r0` addresses
 * separated by commas or whitespace). Display only: the `r0` form identifies
 * nothing and grants nothing, and links keep the plain form.
 *
 * A roster that does not parse is reported in the console and ignored, so the
 * explorer shows every address in the plain form rather than failing to load.
 */
function loadRoster(): ReadonlySet<string> {
  try {
    return parseSwarmRoster(import.meta.env.VITE_SWARM_ROSTER ?? '');
  } catch (err) {
    console.error('VITE_SWARM_ROSTER ignored:', err);
    return new Set();
  }
}

const roster = loadRoster();

/** The text to show for an address: `r0…` for a roster member, else unchanged. */
export function showAddress(address: string): string {
  return displayAddress(address, roster);
}

/**
 * The plain form of an address that may be in the `r0` form (for example one copied from this explorer and pasted
 * into the search): the same account, for RPC queries and comparisons with the plain addresses the node returns.
 * Any other text is returned unchanged.
 */
export function plainAddress(address: string): string {
  return isRaddress(address) ? fromRaddress(address) : address;
}
