<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
namespace App\Http\Middleware;
 

class EmployeeMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // تحقق من أن المستخدم هو من نوع 'employee'
        if (auth()->user()->user_type !== 'employee') {
            return response()->json(['message' => 'Unauthorized'], 403); // إذا لم يكن الموظف
        }

        return $next($request);
    }
}
