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
use InvalidArgumentException;

use Cache;

/**
 * Class EntrustUserTrait
 *
 * @package Zizaco\Entrust\Traits
 */
trait EntrustUserTrait
{
    /**
     * Big block of caching functionality.
     *
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function cachedRoles()
    {
        $userPrimaryKey = $this->primaryKey;
        $cacheKey       = 'entrust_roles_for_user_' . $this->$userPrimaryKey;

        if (Cache::getStore() instanceof TaggableStore) {
            return Cache::tags(config('entrust.role_user_table'))->remember($cacheKey, config('cache.ttl', 60), function () {
                return $this->roles()->get();
            });
        }
        else {
            return Cache::store('array')->remember($cacheKey, 0, function () {
                return $this->roles()->get();
            });
        }
    }

    /**
     * @return $this
     */
    public function flushCache()
    {
        if (Cache::getStore() instanceof TaggableStore) {
            Cache::tags(config('entrust.role_user_table'))->flush();
        }

        return $this;
    }

    /**
     * @param array $options
     * @return mixed
     */
    public function save(array $options = [])
    {
        // Both inserts and updates
        return parent::save($options) ? $this->flushCache() : false;
    }

    /**
     * @param array $options
     * @return mixed
     */
    public function delete(array $options = [])
    {
        // Soft or hard
        return parent::delete($options) ?: false;
    }

    /**
     * @return mixed
     */
    public function restore()
    {
        // Soft delete undo's
        return parent::restore() ? $this->flushCache() : false;
    }

    /**
     * Many-to-Many relations with Role.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function roles()
    {
        return $this->belongsToMany(config('entrust.role'), config('entrust.role_user_table'), config('entrust.user_foreign_key'), config('entrust.role_foreign_key'));
    }

    /**
     * Boot the user model
     * Attach event listener to remove the many-to-many records when trying to delete
     * Will NOT delete any records if the user model uses soft deletes.
     *
     * @return void|bool
     */
    public static function bootEntrustPermissionTrait()
    {
        static::deleting(function ($user) {
            if (!method_exists(config('auth.model'), 'bootSoftDeletes')) {
                $user->roles()->sync([]);
            }

            return true;
        });
    }

    /**
     * Checks if the user has a role by its name.
     *
     * @param string|array $name       Role name or array of role names.
     * @param bool         $requireAll All roles in the array are required.
     *
     * @return bool
     */
    public function hasRole($name, $requireAll = false)
    {
        if (is_array($name)) {
            foreach ($name as $roleName) {
                $hasRole = $this->hasRole($roleName);

                if ($hasRole && !$requireAll) {
                    return true;
                }
                elseif (!$hasRole && $requireAll) {
                    return false;
                }
            }

            // If we've made it this far and $requireAll is FALSE, then NONE of the roles were found
            // If we've made it this far and $requireAll is TRUE, then ALL of the roles were found.
            // Return the value of $requireAll;
            return $requireAll;
        }
        else {
            foreach ($this->cachedRoles() as $role) {
                if ($role->name == $name) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if user has a permission by its name.
     *
     * @param string|array $permission Permission string or array of permissions.
     * @param bool         $requireAll All permissions in the array are required.
     *
     * @return bool
     */
    public function can($permission, $requireAll = false)
    {
        if (is_array($permission)) {
            foreach ($permission as $permName) {
                $hasPerm = $this->can($permName);

                if ($hasPerm && !$requireAll) {
                    return true;
                }
                elseif (!$hasPerm && $requireAll) {
                    return false;
                }
            }

            // If we've made it this far and $requireAll is FALSE, then NONE of the perms were found
            // If we've made it this far and $requireAll is TRUE, then ALL of the perms were found.
            // Return the value of $requireAll;
            return $requireAll;
        }
        else {
            foreach ($this->cachedRoles() as $role) {
                // Validate against the Permission table
                foreach ($role->cachedPermissions() as $perm) {
                    if (str_is($permission, $perm->name)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Checks role(s) and permission(s).
     *
     * @param string|array $roles       Array of roles or comma separated string
     * @param string|array $permissions Array of permissions or comma separated string.
     * @param array        $options     validate_all (true|false) or return_type (boolean|array|both)
     *
     * @throws \InvalidArgumentException
     *
     * @return array|bool
     */
    public function ability($roles, $permissions, $options = [])
    {
        // Convert string to array if that's what is passed in.
        if (!is_array($roles)) {
            $roles = explode(',', $roles);
        }

        if (!is_array($permissions)) {
            $permissions = explode(',', $permissions);
        }

        // Set up default values and validate options.
        if (!isset($options[ 'validate_all' ])) {
            $options[ 'validate_all' ] = false;
        }
        else {
            if ($options[ 'validate_all' ] !== true && $options[ 'validate_all' ] !== false) {
                throw new InvalidArgumentException();
            }
        }

        if (!isset($options[ 'return_type' ])) {
            $options[ 'return_type' ] = 'boolean';
        }
        else {
            if ($options[ 'return_type' ] != 'boolean' &&
                $options[ 'return_type' ] != 'array' &&
                $options[ 'return_type' ] != 'both'
            ) {
                throw new InvalidArgumentException();
            }
        }

        // Loop through roles and permissions and check each.
        $checkedRoles       = [];
        $checkedPermissions = [];

        foreach ($roles as $role) {
            $checkedRoles[ $role ] = $this->hasRole($role);
        }

        foreach ($permissions as $permission) {
            $checkedPermissions[ $permission ] = $this->can($permission);
        }

        // If validate all and there is a false in either
        // Check that if validate all, then there should not be any false.
        // Check that if not validate all, there must be at least one true.
        if (($options[ 'validate_all' ] && !(in_array(false, $checkedRoles) || in_array(false, $checkedPermissions))) ||
            (!$options[ 'validate_all' ] && (in_array(true, $checkedRoles) || in_array(true, $checkedPermissions)))
        ) {
            $validateAll = true;
        }
        else {
            $validateAll = false;
        }

        // Return based on option
        if ($options[ 'return_type' ] == 'boolean') {
            return $validateAll;
        }
        elseif ($options[ 'return_type' ] == 'array') {
            return [
                'roles'       => $checkedRoles,
                'permissions' => $checkedPermissions
            ];
        }
        else {
            return [
                $validateAll,
                [
                    'roles'       => $checkedRoles,
                    'permissions' => $checkedPermissions
                ]
            ];
        }
    }

    /**
     * Alias to eloquent many-to-many relation's attach() method.
     *
     * @param mixed $role
     * @return object $this
     */
    public function attachRole($role)
    {
        if (is_object($role)) {
            $role = $role->getKey();
        }

        if (is_array($role)) {
            $role = $role[ 'id' ];
        }

        $this->roles()->attach($role);

        return $this;
    }

    /**
     * Alias to eloquent many-to-many relation's detach() method.
     *
     * @param mixed $role
     * @return object $this
     */
    public function detachRole($role)
    {
        if (is_object($role)) {
            $role = $role->getKey();
        }

        if (is_array($role)) {
            $role = $role[ 'id' ];
        }

        $this->roles()->detach($role);

        return $this;
    }

    /**
     * Attach multiple roles to a user
     *
     * @param mixed $roles
     * @return object $this
     */
    public function attachRoles($roles)
    {
        foreach ($roles as $role) {
            $this->attachRole($role);
        }

        return $this;
    }

    /**
     * Detach multiple roles from a user
     *
     * @param mixed $roles
     * @return object $this
     */
    public function detachRoles($roles = null)
    {
        if (!$roles) {
            $roles = $this->roles()->get();
        }

        foreach ($roles as $role) {
            $this->detachRole($role);
        }

        return $this;
    }
}