<?php

declare(strict_types=1);

namespace Strukt\Ssl\Csr;

/**
 * Distinctive (subject) name for a certificate signing request.
 *
 * Accepts friendly alias keys and expands them to the OpenSSL distinguished
 * name fields. The alias surface is unchanged from the legacy package:
 * `country`, `loc`, `subLoc`, `org`, `orgUnit`, `common`, `email`.
 */
final class UniqueName
{
    /** @var array<string, string> Alias to OpenSSL field. */
    protected array $keys = [
        'country' => 'countryName',
        'loc' => 'stateOrProvinceName',
        'subLoc' => 'localityName',
        'org' => 'organizationName',
        'orgUnit' => 'organizationalUnitName',
        'common' => 'commonName',
        'email' => 'emailAddress',
    ];

    /** @var array<string, string> Resolved distinguished name. */
    private array $distgName = [];

    /**
     * @param array<string, string> $names Alias-keyed fields.
     */
    public function __construct(array $names)
    {
        foreach ($this->keys as $alias => $field) {
            if (array_key_exists($alias, $names) && $names[$alias] !== null && $names[$alias] !== '') {
                $this->distgName[$field] = (string) $names[$alias];
            }
        }
    }

    /**
     * Returns one resolved field.
     */
    public function get(string $alias): ?string
    {
        $field = $this->keys[$alias] ?? null;

        return $field !== null ? ($this->distgName[$field] ?? null) : null;
    }

    /**
     * All resolved fields, OpenSSL names as keys.
     *
     * @return array<string, string>
     */
    public function getDetails(): array
    {
        return $this->distgName;
    }
}