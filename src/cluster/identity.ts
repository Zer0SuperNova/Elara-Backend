import { randomUUID } from 'node:crypto';

/**
 * Represents the current process identity.
 */
class Identity {
    private readonly id: string;

    /**
     * Creates a new identity using the host name or a random UUID.
     */
    constructor() {
        this.id = process.env.HOSTNAME ?? randomUUID();
    }

    /**
     * Gets the node identifier.
     */
    get nodeId(): string {
        return this.id;
    }

    /**
     * Returns the identity as a string.
     */
    toString(): string {
        return this.id;
    }
}

/**
 * Shared process identity instance.
 */
const identity = new Identity();

export default identity;