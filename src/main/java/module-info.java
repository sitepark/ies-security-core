module com.sitepark.ies.security.core {
  exports com.sitepark.ies.security.core.domain.entity;
  exports com.sitepark.ies.security.core.domain.value;
  exports com.sitepark.ies.security.core.domain.exception;
  exports com.sitepark.ies.security.core.domain.service;
  exports com.sitepark.ies.security.core.port;
  exports com.sitepark.ies.security.core.usecase.totp;
  exports com.sitepark.ies.security.core.usecase.webauthn;
  exports com.sitepark.ies.security.core.usecase.token;
  exports com.sitepark.ies.security.core.usecase.session;
  exports com.sitepark.ies.security.core.usecase.oidc;
  exports com.sitepark.ies.security.core.usecase.password;

  requires org.apache.logging.log4j;
  requires jakarta.inject;
  requires com.fasterxml.jackson.annotation;
  requires com.fasterxml.jackson.databind;
  requires com.fasterxml.jackson.datatype.jdk8;
  requires com.fasterxml.jackson.datatype.jsr310;
  requires com.sitepark.ies.sharedkernel;
  requires static com.github.spotbugs.annotations;
  requires static org.jetbrains.annotations;
  requires jsr305;

  opens com.sitepark.ies.security.core.port;
  opens com.sitepark.ies.security.core.domain.entity;
  opens com.sitepark.ies.security.core.domain.value;
}
