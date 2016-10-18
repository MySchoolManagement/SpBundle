<?php

/*
 * This file is part of the LightSAML SP-Bundle package.
 *
 * (c) Milos Tomic <tmilos@lightsaml.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace LightSaml\SpBundle\Model\Protocol;

use LightSaml\Context\Profile\MessageContext;
use LightSaml\Model\Assertion\Issuer;
use LightSaml\Model\Assertion\NameID;
use LightSaml\Model\Metadata\SingleLogoutService;
use LightSaml\Model\Protocol\LogoutRequest;
use LightSaml\Model\Protocol\LogoutResponse;
use LightSaml\Helper as LightSamlHelper;
use LightSaml\Model\Protocol\SamlMessage;
use LightSaml\Model\Protocol\Status;
use LightSaml\Model\Protocol\StatusCode;
use LightSaml\SamlConstants;
use LightSaml\SpBundle\Exception\IdPZeroSingleLogoutEndpointsException;
use LightSaml\State\Sso\SsoSessionState;
use LightSaml\Store\EntityDescriptor\EntityDescriptorStoreInterface;

/**
 * Class LogoutMessageFactory.
 */
class LogoutMessageContextFactory
{
    /** @var string */
    private $spEntityId;
    /** @var EntityDescriptorStoreInterface */
    private $entityDescriptorStore;

    /**
     * LogoutMessageFactory constructor.
     *
     * @param string                         $spEntityId
     * @param EntityDescriptorStoreInterface $entityDescriptorStore
     */
    public function __construct($spEntityId, EntityDescriptorStoreInterface $entityDescriptorStore)
    {
        $this->spEntityId = $spEntityId;
        $this->entityDescriptorStore = $entityDescriptorStore;
    }

    /**
     * @param SsoSessionState $sessionState
     *
     * @return MessageContext
     *
     * @throws IdPZeroSingleLogoutEndpointsException
     */
    public function request(SsoSessionState $sessionState)
    {
        $idpEntityId = $sessionState->getIdpEntityId();
        $logoutService = $this->getSingleLogoutService($idpEntityId);

        if ($logoutService === null) {
            throw new IdPZeroSingleLogoutEndpointsException();
        }

        $logoutRequest = new LogoutRequest();
        $this->initMessage($logoutRequest);

        $logoutRequest->setSessionIndex($sessionState->getSessionIndex());
        $logoutRequest->setNameID(new NameID(
            $sessionState->getNameId(), $sessionState->getNameIdFormat()
        ));
        $logoutRequest->setDestination($logoutService->getLocation());

        return $this->surroundWithContext($logoutRequest, $logoutService);
    }

    /**
     * @param LogoutRequest $ipRequest
     *
     * @return MessageContext
     */
    public function response(LogoutRequest $ipRequest)
    {
        $logoutResponse = new LogoutResponse();
        $this->initMessage($logoutResponse);

        $logoutResponse->setRelayState($ipRequest->getRelayState());
        $logoutResponse->setInResponseTo($ipRequest->getID());
        $logoutResponse->setStatus(new Status(
            new StatusCode(SamlConstants::STATUS_SUCCESS)
        ));
        $logoutResponse->setDestination($this->getSingleLogoutServiceLocation());

        return $this->surroundWithContext($logoutResponse);
    }

    /**
     * @param SamlMessage $samlMessage
     */
    private function initMessage(SamlMessage $samlMessage)
    {
        $samlMessage
            ->setID(LightSamlHelper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setIssuer(new Issuer($this->spEntityId));
    }

    private function getSingleLogoutService($idpEntityId)
    {
        $idpSsoDescriptor = $this->getIdpSsoDescriptor($idpEntityId);

        if ($idpSsoDescriptor !== null) {
            return $idpSsoDescriptor->getFirstSingleLogoutService();
        }

        return null;
    }

    /**
     * @param string $idpEntityId
     *
     * @return \LightSaml\Model\Metadata\IdpSsoDescriptor|null
     */
    private function getIdpSsoDescriptor($idpEntityId)
    {
        $entityDescriptor = $this->entityDescriptorStore->get($idpEntityId);
        $idpDescriptors = $entityDescriptor ? $entityDescriptor->getAllIdpSsoDescriptors() : [];

        // find the first sso descriptor with an sso logout
        foreach ($idpDescriptors as $ssoDescriptor) {
            if ($ssoDescriptor->getFirstSingleLogoutService() !== null) {
                return $ssoDescriptor;
            }
        }

        return null;
    }

    /**
     * @param SamlMessage           $samlMessage
     * @param SingleLogoutService   $singleLogoutService
     *
     * @return MessageContext
     */
    private function surroundWithContext(SamlMessage $samlMessage, SingleLogoutService $singleLogoutService)
    {
        $context = new MessageContext();
        $context->setMessage($samlMessage);
        $context->setBindingType($singleLogoutService->getBinding());

        return $context;
    }
}
