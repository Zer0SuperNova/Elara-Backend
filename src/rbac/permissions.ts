export const Permission = {
    Wildcard:   '*',
    AccessBeta: 'access.beta',
    Admin:     'admin',
} as const;

export type Permission = typeof Permission[keyof typeof Permission];