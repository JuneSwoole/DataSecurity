<?php
/*
 * @Author: juneChen && juneswoole@163.com
 * @Date: 2023-07-21 10:13:16
 * @LastEditors: juneChen && juneswoole@163.com
 * @LastEditTime: 2023-07-24 10:48:15
 * 
 */

declare(strict_types=1);

namespace June\DataSecurity;

trait Singleton
{
    private static $instance;

    /**
     * @param mixed ...$args
     * @return static
     */
    static function getInstance(...$args)
    {
        if (!isset(static::$instance)) {
            static::$instance = new static(...$args);
        }
        return static::$instance;
    }
}
