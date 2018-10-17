package com.syswin.temail.kms.sdk;

import com.syswin.temail.kms.vault.KeyAwareVault;
import com.syswin.temail.kms.vault.Vault;
import com.syswin.temail.kms.vault.VaultKeeper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
class KmsSdkAutoConfiguration {

  @Bean
  @ConditionalOnExpression("!'${app.vault.registry.url}'.isEmpty()")
  KeyAwareVault vaultKeeper(@Value("${app.vault.registry.url}") String baseUrl, @Value("${app.vault.registry.token}") String token) {
    return VaultKeeper.keyAwareVault(baseUrl, token);
  }

  @Bean
  @ConditionalOnExpression("'${app.vault.registry.url}'.isEmpty()")
  Vault vault() {
    return VaultKeeper.vault();
  }
}
