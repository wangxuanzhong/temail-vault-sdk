package com.syswin.temail.kms.sdk;

import com.syswin.temail.kms.vault.VaultKeeper;
import com.syswin.temail.kms.vault.cache.ICache;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.ehcache.EhCacheCacheManager;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
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
  public VaultKeeper vaultKeeper(ICache kmsCache) {
    return new VaultKeeper(UUID.randomUUID().toString(), kmsCache);
  }

  @Bean
  public TSBService itsbService(CipherService cipherService, ICache iCache) {
    return new TSBService(cipherService, iCache);
  }


  @Bean
  public CipherService cipherService(KmsProperties kmsProperties, RestTemplate restTemplate, VaultKeeper vaultKeeper) {
    return new CipherService(kmsProperties, restTemplate, vaultKeeper);
  }

  @Bean
  public ICache kmsCache(ApplicationContext applicationContext) {
    EhCacheCacheManager ehCacheCacheManager = applicationContext.getBean(EhCacheCacheManager.class);
    return new KmsCache(ehCacheCacheManager);
  }
}
