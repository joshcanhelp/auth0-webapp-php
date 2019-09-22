<?php
namespace Auth0\Auth\Store;

interface StoreInterface
{
    /**
     * @param string $key
     * @param mixed  $value
     */
    public function set($key, $value);

    /**
     * @param  string     $key
     * @param  mixed|null $default
     * @return mixed
     */
    public function get($key, $default = null);

    /**
     * @param  string $key
     * @return mixed
     */
    public function delete($key);
}
