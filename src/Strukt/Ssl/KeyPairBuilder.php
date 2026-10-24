<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Builds a key pair whose files live under a configurable directory and name.
 *
 *   KeyPairBuilder::make($dir, $name)->makeKeyPair()   direct generation
 */
final class KeyPairBuilder
{
    private string $dir;

    private string $name;

    private array $configOptions = [];

    /**
     * @param string $dir Directory for the generated files.
     * @param string $name Base file name without extension.
     */
    public function __construct(string $dir = 'keys/', string $name = 'key')
    {
        $this->dir = $dir;
        $this->name = $name;
    }

    /**
     * Changes the target directory.
     *
     * @return static Builder self.
     */
    public function setDirectory(string $dir): static
    {
        $this->dir = $dir;

        return $this;
    }

    /**
     * Changes the base name.
     *
     * @return static Builder self.
     */
    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Overrides the OpenSSL config options.
     *
     * @return static Builder self.
     */
    public function setConfigOptions(array $configOptions): static
    {
        $this->configOptions = $configOptions;

        return $this;
    }

    /**
     * Generates the pair.
     */
    public function makeKeyPair(): KeyPair
    {
        return KeyPair::make($this->dir, $this->name, $this->configOptions);
    }

    /**
     * Builds a builder, optionally pre-seeding directory and name.
     *
     * @return static New builder.
     */
    public static function make(?string $dir = null, ?string $name = null): static
    {
        $builder = new self();

        if ($dir !== null) {
            $builder->setDirectory($dir);
        }

        if ($name !== null) {
            $builder->setName($name);
        }

        return $builder;
    }
}