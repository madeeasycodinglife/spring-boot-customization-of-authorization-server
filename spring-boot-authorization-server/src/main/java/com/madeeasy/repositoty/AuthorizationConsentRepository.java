package com.madeeasy.repositoty;

import com.madeeasy.entity.AuthorizationConsent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorizationConsentRepository extends JpaRepository<AuthorizationConsent, AuthorizationConsent.AuthorizationConsentId> {

    Optional<AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
