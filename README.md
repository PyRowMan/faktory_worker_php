Currently very much WIP!

## Install via composer

```
composer require basekit/faktory_worker_php
```

## Add jobs

```php
$client = new FaktoryClient($faktoryHost, $faktoryPort, $faktoryPassword);
$job = new FaktoryJob($id, $type, $args);
$client->push($job);
```

## Process jobs

```php
$client = new FaktoryClient($faktoryHost, $faktoryPort, $faktoryPassword);
$worker = new FaktoryWorker($client);
$worker->register('somejob', function ($job) {
    echo "You got the job buddy!\n";
    var_dump($job);
});

$worker->setQueues(['critical', 'default', 'bulk']);
$worker->run();
```
