<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
 use Illuminate\Support\Facades\Gate;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The policy mappings for the application.
     *
     * @var array<class-string, class-string>
     */
    protected $policies = [
        // 'App\Models\Model' => 'App\Policies\ModelPolicy',
    ];

    /**
     * Register any authentication / authorization services.
     */

    public function boot()
    {
        $this->registerPolicies();
    
        // تعريف الصلاحية
        Gate::define('manage-slots', function ($user) {
            return $user->user_type === 'employee'; // فقط الموظفون يمكنهم إضافة المواقف
        });
    }
}
