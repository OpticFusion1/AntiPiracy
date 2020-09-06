<?php

namespace RAL\XF\Pub\View\Attachment;

class View extends XFCP_View {
	public function renderRaw() {
        /** @var \XF\Entity\Attachment $attachment */
        $attachment = $this->params['attachment'];

        if (!empty($this->params['return304'])) {
            $this->response
                ->httpCode(304)
                ->removeHeader('last-modified');

            return '';
        }

        if ($this->params['inject'] && $this->endsWith($attachment->filename, ".jar")
            || $this->endsWith($attachment->filename, ".zip")) {
            $resource = new ResponseStream(str_replace('internal-data://attachments', "/home/xbrowniecodez/web/internal_data/attachments", $attachment->Data->getAbstractedDataPath()), $this->params['user_id'], $this->params['resource_id'], $this->params['link']);
            // ^^^ CHANGE THIS ^^^
			$this->response
                ->setAttachmentFileParams($attachment->filename, $attachment->extension)
                ->header('Content-Length', strlen($resource));
            return $resource;
        } else {
            $this->response
                ->setAttachmentFileParams($attachment->filename, $attachment->extension)
                ->header('ETag', '"' . $attachment->attach_date . '"');
            $resource = \XF::fs()->readStream($attachment->Data->getAbstractedDataPath());
            return $this->response->responseStream($resource, $attachment->file_size);
        }
    }

    public function endsWith($haystack, $needle) {
        $length = strlen($needle);
        if ($length == 0) {
            return true;
        }

        return (substr($haystack, -$length) === $needle);
    }
}