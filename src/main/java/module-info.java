module com.sitepark.ies.security.core {
  exports com.sitepark.ies.security.core.domain.entity;
  exports com.sitepark.ies.security.core.domain.value;
  exports com.sitepark.ies.security.core.domain.exception;
  exports com.sitepark.ies.security.core.port;
  exports com.sitepark.ies.security.core.usecase;
  exports com.sitepark.ies.security.core.usecase.authentication;

  requires org.apache.logging.log4j;
  requires jakarta.inject;
  requires com.fasterxml.jackson.annotation;
  requires com.fasterxml.jackson.databind;
  requires com.fasterxml.jackson.datatype.jdk8;
  requires com.fasterxml.jackson.datatype.jsr310;
  requires com.sitepark.ies.sharedkernel;
  requires static com.github.spotbugs.annotations;
  requires static org.jetbrains.annotations;

  opens com.sitepark.ies.security.core.port;
  opens com.sitepark.ies.security.core.domain.entity;
}
