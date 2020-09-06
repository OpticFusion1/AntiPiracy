<?php

namespace RAL\XF\Pub\View\Attachment;

class ResponseStream {
    protected $resource = null;

    protected $contents = null;

    protected $userId = '%%__USER__%%';
    protected $resourceId = '%%__RESOURCE__%%';
    protected $link = '';

    public function __construct($resource, $userId, $resourceId, $link) {
        $this->resource = $resource;
        $this->userId = $userId;
        $this->resourceId = $resourceId;
        $this->link = $link;
    }

    public function __toString() {
        return $this->getContents();
    }

    public function output() {
        if ($this->contents === null) {
            fpassthru($this->resource);
        } else {
            echo $this->contents;
        }
    }

    public function getStream() {
        return $this->resource;
    }

    public function getContents() {
        if ($this->contents === null) {
            try {
                $data = $this->resource . '|' . $this->userId . '|' . $this->resourceId . '|' . $this->link . PHP_EOL;
                $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

                socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array("sec" => 60, "usec" => 0));
                socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, array("sec" => 10, "usec" => 0));

                socket_connect($socket, '127.0.0.1', 35565); #35565

                socket_write($socket, $data);

                while ($rcvdata = socket_read($socket, 1024, PHP_BINARY_READ)) {
                    $this->contents .= $rcvdata;
                }

                socket_close($socket);

                if ($this->contents === null || $this->contents === '') throw new \Exception("Contents are empty");
            } catch (\Exception $ex) {
                $this->contents = file_get_contents($this->resource);
            }
        }

        return $this->contents;
    }
}