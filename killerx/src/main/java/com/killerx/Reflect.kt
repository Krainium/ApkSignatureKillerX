package com.killerx

import java.lang.reflect.Field

/** Small reflection helpers shared by the hooks. */
internal object Reflect {

    /** Find a declared field on [clazz] or any superclass, made accessible. */
    fun field(clazz: Class<*>, name: String): Field {
        var c: Class<*>? = clazz
        while (c != null && c != Any::class.java) {
            try {
                return c.getDeclaredField(name).apply { isAccessible = true }
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            }
        }
        throw NoSuchFieldException("$name not found on ${clazz.name} or its supers")
    }

    /** Read a static field, swallowing anything that goes wrong. */
    fun staticOrNull(clazz: Class<*>, name: String): Any? = try {
        field(clazz, name).get(null)
    } catch (_: Throwable) {
        null
    }

    /** Call a no-arg method reflectively, swallowing failures. */
    fun callQuietly(target: Any, method: String) {
        try {
            target.javaClass.getMethod(method).invoke(target)
        } catch (_: Throwable) {
        }
    }
}
