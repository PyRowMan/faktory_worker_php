<?php

require __DIR__ . '/../vendor/autoload.php';

use BaseKit\Faktory\FaktoryClient;
use BaseKit\Faktory\FaktoryWorker;

if (false === class_exists('Monolog\Logger')) {
    die("Monolog is required to run these examples.\r\nRun: composer require monolog/monolog\r\n");
}

$logger = new Monolog\Logger('worker');
$handler = new Monolog\Handler\StreamHandler('php://stdout', Monolog\Logger::DEBUG);
$logger->pushHandler($handler);

$client = new FaktoryClient(getenv('FAKTORY_HOST'), getenv('FAKTORY_PORT'), getenv('FAKTORY_PASSWORD') ?? null);
$worker = new FaktoryWorker($client, $logger);
$worker->register('somejob', function ($job) {
    echo "You got the job buddy!\n";
    var_dump($job);
});

$worker->setQueues(['critical', 'default', 'bulk']);
$daemonize = true;
$worker->run($daemonize);
