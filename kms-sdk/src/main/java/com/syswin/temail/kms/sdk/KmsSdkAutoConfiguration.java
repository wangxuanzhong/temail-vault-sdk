package com.syswin.temail.kms.sdk;

import com.syswin.temail.kms.sdk.condition.UnWindowsCondition;
import com.syswin.temail.kms.sdk.condition.WindowsCondition;
import com.syswin.temail.kms.vault.KeyAwareVault;
import com.syswin.temail.kms.vault.VaultKeeper;
import com.syswin.temail.kms.vault.cache.ICache;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.ehcache.EhCacheCacheManager;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableConfigurationProperties(KmsProperties.class)
@EnableCaching
public class KmsSdkAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }

  @Bean
  public KeyAwareVault vaultKeeper(@Value("${temail.vault.registry.url}") String baseUrl) {
    return VaultKeeper.keyAwareVault(baseUrl, UUID.randomUUID().toString());
  }

  @Bean
  public TSBService itsbService(CipherService cipherService, ICache iCache) {
    return new TSBService(cipherService, iCache);
  }

  @Bean
  @Conditional(WindowsCondition.class)
  public CipherService winCipherService(KmsProperties kmsProperties, RestTemplate restTemplate, KeyAwareVault vaultKeeper) {
    return new NullCipherService(kmsProperties, restTemplate, vaultKeeper);
  }


  @Bean
  @Conditional(UnWindowsCondition.class)
  public CipherService cipherService(KmsProperties kmsProperties, RestTemplate restTemplate, KeyAwareVault vaultKeeper) {
    return new CipherService(kmsProperties, restTemplate, vaultKeeper);
  }

  @Bean
  public ICache kmsCache(ApplicationContext applicationContext) {
    EhCacheCacheManager ehCacheCacheManager = applicationContext.getBean(EhCacheCacheManager.class);
    return new KmsCache(ehCacheCacheManager);
  }
}
