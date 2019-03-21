<?php

namespace BaseKit\Faktory;

use Monolog\Logger;

class FaktoryClient
{
    const STOP = 'STOP';
    const QUIET = 'QUIET';
    /**
     * @var string
     */
    private $faktoryHost;

    /**
     * @var int
     */
    private $faktoryPort;

    private $wid;

    private $pid;

    private $password;

    /**
     * @return resource
     */
    private $connection;

    /** @var LoggerInterface $logger */
    private $logger;

    /** @var $time \DateTime */
    private $time;

    /**
     * FaktoryClient constructor.
     * @param string $faktoryHost
     * @param int $faktoryPort
     * @param string|null $password
     */
    public function __construct(string $faktoryHost, int $faktoryPort, ?string $password = null)
    {
        $this->faktoryHost = $faktoryHost;
        $this->faktoryPort = $faktoryPort;
        $this->password = $password;
        $this->wid = uniqid();
        $this->pid = rand(1, 99999);
        $this->time = new \DateTime();
    }

    /**
     * @return LoggerInterface
     */
    public function getLogger()
    {
        return $this->logger;
    }

    /**
     * @param LoggerInterface $logger
     * @return FaktoryClient
     */
    public function setLogger($logger)
    {
        $this->logger = $logger;
        return $this;
    }

    public function hasLogger()
    {
        return !empty($this->logger);
    }

    /**
     * @return mixed
     */
    public function getConnection()
    {
        if(empty($this->connection))
            $this->connection = $this->connect();
        return $this->connection;
    }

    public function push(FaktoryJob $job): void
    {
        $socket = $this->getConnection();
        $this->writeLine($socket, 'PUSH', json_encode($job));
        $this->close($socket);
    }

    public function fetch(array $queues)
    {
        $socket = $this->getConnection();

        $response = $this->writeLine($socket, 'FETCH', implode(' ', $queues));

        $char = $response[0];
        if ($char === '$') {
            $count = trim(substr($response, 1, strpos($response, "\r\n")));
            $data = null;
            if ($count > 0) {
                $data = substr($response, strlen($count) + 1);
                $this->close($socket);
                return json_decode($data, true);
            }

            return $data;
        }

        $this->close($socket);

        return $response;
    }

    /**
     * @param string $jobId
     * @param Logger|null $logger
     */
    public function ack(string $jobId, ?Logger $logger): void
    {
        $socket = $this->getConnection();
        $response = $this->writeLine($socket, 'ACK', json_encode(['jid' => $jobId]));
        var_dump($response);
        $this->close($socket);
        $logger->debug("ACK sent for jobId : " . $jobId);
    }

    /**
     * @param string $jobId
     */
    public function fail(string $jobId): void
    {
        $socket = $this->getConnection();
        $this->writeLine($socket, 'FAIL', json_encode(['jid' => $jobId]));
        $this->close($socket);
    }

    /**
     * @return resource
     * @throws \Exception
     */
    private function connect()
    {
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_connect($socket, $this->faktoryHost, $this->faktoryPort);

        $response = $this->readLine($socket);
        if (!strpos($response, 'HI')) {
            throw new \Exception('Hi not received :(');
        }
        $response = json_decode(str_replace("+HI ", "", $response));

        $data = [
            'wid' => $this->wid,
            'hostname' => gethostname(),
            'labels' => ['PHP'],
            'pid' => $this->pid,
            'v' => 2
        ];
        if (isset($response->s)) {
            if (empty($this->password))
                throw new \Exception('A password is required');
            $data["pwdhash"] = $this->hash($this->password, $response->s, $response->i ?? 1);
        }

        $response = $this->writeLine($socket, 'HELLO', json_encode($data));
        if (strpos($response, 'ERR'))
            throw new \Exception($response);
        return $socket;
    }

    private function readLine($socket, int $length = 1024): string
    {
        $bytes = socket_read($socket, $length, PHP_BINARY_READ);
        while (strpos($bytes, "\r\n") === false) {
            $bytes .= socket_read($socket, $length - strlen($bytes), PHP_BINARY_READ);
        }
        return $bytes;
    }

    private function writeLine($socket, string $command, string $json, $shouldRespond = true): ?string
    {
        $buffer = $command . ' ' . $json . "\r\n";
        socket_write($socket, $buffer, strlen($buffer));
        $this->log($command);
        $read = ($shouldRespond) ? $this->readLine($socket) : null;
        return $read;
    }

    /**
     * @param $socket
     */
    private function close($socket): void
    {
        unset($this->connection);
        socket_close($socket);
    }

    public function end(): void
    {
        $socket = $this->getConnection();
        $response = $this->writeLine($socket, 'END', '', false);
        $this->close($socket);
    }

    private function hash($pwd, string $salt, int $iterations)
    {
        $string = $pwd . $salt;
        $bytes = unpack('C*', $string);
        $hash = hash('sha256', $string, true);
        if ($iterations > 1) {
            for ($i = 1; $i < $iterations; $i++) {
                $hash = hash('sha256', $hash, true);
            }
        }
        return bin2hex($hash);
    }

    /**
     * @param $message
     */
    public function log($message)
    {
        if ($this->hasLogger()) {
            $this->logger->debug($message);
        }
    }

    public function beat()
    {
        $diff = (new \DateTime())->getTimestamp() - $this->time->getTimestamp();
        if ($diff < 2) return false;
        $socket = $this->getConnection();
        $response = $this->writeLine($socket, 'BEAT', json_encode(['wid' => $this->wid]));
        $this->close($socket);
        if (!strpos($response, 'OK')) {
            if (strpos($response, '$21') !== false)
                return self::STOP;
            elseif (strpos($response, '$17') !== false)
                return self::QUIET;
            else
                throw new \Exception("Unknown error triggered from the server");
        }
        $this->time = new \DateTime();
        return false;
    }

}
