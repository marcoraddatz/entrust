<?php

namespace Zizaco\Entrust\Traits;

/**
 * This file is part of Entrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Zizaco\Entrust
 */

use Illuminate\Cache\TaggableStore;

use Cache;

/**
 * Class EntrustRoleTrait
 *
 * @package Zizaco\Entrust\Traits
 */
trait EntrustRoleTrait
{
    /**
     * Big block of caching functionality.
     *
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function cachedPermissions()
    {
        $rolePrimaryKey = $this->primaryKey;
        $cacheKey       = 'entrust_permissions_for_role_' . $this->$rolePrimaryKey;

        if (Cache::getStore() instanceof TaggableStore) {
            return Cache::tags(config('entrust.permission_role_table'))->remember($cacheKey, config('cache.ttl', 60), function () {
                return $this->perms()->get();
            });
        }
        else {
            return Cache::store('array')->remember($cacheKey, 0, function () {
                return $this->perms()->get();
            });
        }
    }

    /**
     * @return mixed
     */
    protected function flushCache()
    {
        if (Cache::getStore() instanceof TaggableStore) {
            Cache::tags(config('entrust.permission_role_table'))->flush();
        }

        return $this;
    }

    /**
     * @param array $options
     * @return bool
     */
    public function save(array $options = [])
    {
        // Both inserts and updates
        return parent::save($options) ? $this->flushCache() : false;
    }

    /**
     * @param array $options
     * @return bool
     */
    public function delete(array $options = [])
    {
        // Soft or hard
        return parent::delete($options) ? $this->flushCache() : false;
    }

    /**
     * @return bool
     */
    public function restore()
    {
        // Soft delete undo's
        return !parent::restore() ? $this->flushCache() : false;
    }

    /**
     * Many-to-Many relations with the user model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function users()
    {
        return $this->belongsToMany(config('auth.providers.users.model'), config('entrust.role_user_table'), config('entrust.role_foreign_key'), config('entrust.user_foreign_key'));
    }

    /**
     * Many-to-Many relations with the permission model.
     * Named "perms" for backwards compatibility. Also because "perms" is short and sweet.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function perms()
    {
        return $this->belongsToMany(config('entrust.permission'), config('entrust.permission_role_table'), config('entrust.role_foreign_key'), config('entrust.permission_foreign_key'));
    }

    /**
     * Boot the role model
     * Attach event listener to remove the many-to-many records when trying to delete
     * Will NOT delete any records if the role model uses soft deletes.
     *
     * @return void|bool
     */
    public static function bootEntrustPermissionTrait()
    {
        static::deleting(function ($role) {
            if (!method_exists(config('entrust.role'), 'bootSoftDeletes')) {
                $role->users()->sync([]);
                $role->perms()->sync([]);
            }

            return true;
        });
    }

    /**
     * Checks if the role has a permission by its name.
     *
     * @param string|array $name       Permission name or array of permission names.
     * @param bool         $requireAll All permissions in the array are required.
     *
     * @return bool
     */
    public function hasPermission($name, $requireAll = false)
    {
        if (is_array($name)) {
            foreach ($name as $permissionName) {
                $hasPermission = $this->hasPermission($permissionName);

                if ($hasPermission && !$requireAll) {
                    return true;
                }
                elseif (!$hasPermission && $requireAll) {
                    return false;
                }
            }

            // If we've made it this far and $requireAll is FALSE, then NONE of the permissions were found
            // If we've made it this far and $requireAll is TRUE, then ALL of the permissions were found.
            // Return the value of $requireAll;
            return $requireAll;
        }
        else {
            foreach ($this->cachedPermissions() as $permission) {
                if ($permission->name == $name) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Save the inputted permissions.
     *
     * @param mixed $inputPermissions
     *
     * @return object $this
     */
    public function savePermissions($inputPermissions)
    {
        if (!empty($inputPermissions)) {
            $this->perms()->sync($inputPermissions);
        }
        else {
            $this->perms()->detach();
        }

        return $this;
    }

    /**
     * Attach permission to current role.
     *
     * @param object|array $permission
     *
     * @return object $this
     */
    public function attachPermission($permission)
    {
        if (is_object($permission)) {
            $permission = $permission->getKey();
        }

        if (is_array($permission)) {
            $permission = $permission[ 'id' ];
        }

        $this->perms()->attach($permission);

        return $this;
    }

    /**
     * Detach permission from current role.
     *
     * @param object|array $permission
     *
     * @return object $this
     */
    public function detachPermission($permission)
    {
        if (is_object($permission)) {
            $permission = $permission->getKey();
        }

        if (is_array($permission)) {
            $permission = $permission[ 'id' ];
        }

        $this->perms()->detach($permission);

        return $this;
    }

    /**
     * Attach multiple permissions to current role.
     *
     * @param mixed $permissions
     *
     * @return object $this
     */
    public function attachPermissions($permissions)
    {
        foreach ($permissions as $permission) {
            $this->attachPermission($permission);
        }

        return $this;
    }

    /**
     * Detach multiple permissions from current role
     *
     * @param mixed $permissions
     *
     * @return object $this
     */
    public function detachPermissions($permissions = null)
    {
        if (!$permissions) {
            $permissions = $this->perms()->get();
        }

        foreach ($permissions as $permission) {
            $this->detachPermission($permission);
        }

        return $this;
    }
}