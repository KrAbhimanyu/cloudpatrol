/**
 * The shape of the sign-in form state.
 *
 * Kept out of `actions.ts` because that module is marked `"use server"` and
 * must export only async server functions. A plain object exported from there
 * would be treated as a server reference, which is at best fragile.
 */

export interface AuthActionState {
  error: string | null;
  /** Set when sign-up succeeded and the user must confirm by email. */
  notice: string | null;
}

export const EMPTY_AUTH_STATE: AuthActionState = { error: null, notice: null };
