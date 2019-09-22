<?php

namespace Auth0\Auth\Cache;

use Auth0\Auth\Store\SessionStore;
use Psr\SimpleCache\CacheInterface;

class SessionCache implements CacheInterface
{
    private $defaultTtl;
    private $store;

    public function __construct( $defaultTtl = 3600 )
    {
        $this->defaultTtl = 3600;
        $this->store = new SessionStore();
    }

    /**
     * Fetches a value from the cache.
     *
     * @param string $key     The unique key of this item in the cache.
     * @param mixed  $default Default value to return if the key does not exist.
     *
     * @return mixed The value of the item from the cache, or $default in case of cache miss.
     */
    public function get($key, $default = null)
    {
        return $this->has($key) ? $this->store->get($key)['value'] : $default;
    }

    /**
     * Persists data in the cache, uniquely referenced by a key with an optional expiration TTL time.
     *
     * @param string                 $key   The key of the item to store.
     * @param mixed                  $value The value of the item to store, must be serializable.
     * @param null|int|\DateInterval $ttl   Optional. The TTL value of this item. If no value is sent and
     *                                      the driver supports TTL then the library may set a default value
     *                                      for it or let the driver take care of that.
     *
     * @return bool True on success and false on failure.
     */
    public function set($key, $value, $ttl = null)
    {
        $to_store = [
            'value' => $value,
            'exp' => time() + ( $ttl ?? $this->defaultTtl ),
        ];
        $this->store->set($key, $to_store);
        return true;
    }

    /**
     * Delete an item from the cache by its unique key.
     *
     * @param string $key The unique cache key of the item to delete.
     *
     * @return bool True if the item was successfully removed. False if there was an error.
     */
    public function delete($key)
    {
        $this->store->delete($key);
        return true;
    }

    /**
     * Wipes clean the entire cache's keys.
     *
     * @return bool True on success and false on failure.
     */
    public function clear()
    {
        $this->store->clear();
        return true;
    }

    /**
     * Obtains multiple cache items by their unique keys.
     *
     * @param iterable $keys    A list of keys that can obtained in a single operation.
     * @param mixed    $default Default value to return for keys that do not exist.
     *
     * @return iterable A list of key => value pairs. Cache keys that do not exist or are stale will have $default as value.
     */
    public function getMultiple($keys, $default = null)
    {
        if (! is_iterable($keys) ) {
            return [];
        }

        $found_items = [];
        foreach ( $keys as $key ) {
            $found_items[$key] = $this->get($key, $default);
        }

        return $found_items;
    }

    /**
     * Persists a set of key => value pairs in the cache, with an optional TTL.
     *
     * @param iterable               $values A list of key => value pairs for a multiple-set operation.
     * @param null|int|\DateInterval $ttl    Optional. The TTL value of this item. If no value is sent and
     *                                       the driver supports TTL then the library may set a default value
     *                                       for it or let the driver take care of that.
     *
     * @return bool True on success and false on failure.
     */
    public function setMultiple($values, $ttl = null)
    {
        if (! is_iterable($values) ) {
            return false;
        }

        foreach ( $values as $key => $value ) {
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    /**
     * Deletes multiple cache items in a single operation.
     *
     * @param iterable $keys A list of string-based keys to be deleted.
     *
     * @return bool True if the items were successfully removed. False if there was an error.
     */
    public function deleteMultiple($keys)
    {
        if (! is_iterable($keys) ) {
            return false;
        }

        foreach ( $keys as $key ) {
            $this->store->delete($key);
        }

        return true;
    }

    /**
     * Determines whether an item is present in the cache.
     *
     * @param string $key The cache item key.
     *
     * @return bool
     */
    public function has($key)
    {
        $stored_value = $this->store->get($key);

        if (! $stored_value ) {
            return false;
        }

        if (time() > $stored_value['exp'] ) {
            $this->delete($key);
            return false;
        }

        return true;
    }
}
