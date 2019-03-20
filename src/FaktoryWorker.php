<?php
declare(strict_types=1);

namespace BaseKit\Faktory;

use Psr\Log\LoggerInterface;

class FaktoryWorker
{
    /**
     * @var FaktoryClient
     */
    private $client;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var array
     */
    private $queues = [];

    /**
     * @var array
     */
    private $jobTypes = [];

    /**
     * @var bool
     */
    private $stop = false;

    public function __construct(FaktoryClient $client, LoggerInterface $logger)
    {
        $this->client = $client;
        $this->logger = $logger;
    }

    public function setQueues(array $queues) : void
    {
        $this->queues = $queues;
    }

    /**
     * @param string $jobType
     * @param callable $callable
     */
    public function register(string $jobType, callable $callable) : void
    {
        $this->jobTypes[$jobType] = $callable;
    }

    /**
     * @param bool $daemonize
     * @throws \Exception
     */
    public function run(bool $daemonize = false) : void
    {
        pcntl_async_signals(true);

        pcntl_signal(SIGTERM, function ($signo) {
            exit(0);
        });

        pcntl_signal(SIGINT, function ($signo) {
            exit(0);
        });

        do {
            $job = $this->client->fetch($this->queues);
            if ($job !== null) {
                $this->logger->debug($job['jid']);

                $callable = $this->jobTypes[$job['jobtype']];

                $pid = pcntl_fork();
                if ($pid === -1) {
                    throw new \Exception('Could not fork');
                }

                if ($pid > 0) {
                    pcntl_wait($status);
                } else {
                    try {
                        call_user_func($callable, $job);
                        $this->client->ack($job['jid']);
                    } catch (\Exception $e) {
                        $this->client->fail($job['jid']);
                    } finally {
                        exit(0);
                    }
                }
            }
            usleep(100);
        } while($daemonize && !$this->stop);
    }
}
