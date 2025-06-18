module com.sitepark.ies.security.core {
  exports com.sitepark.ies.sharedkernel.security.annotation;
  exports com.sitepark.ies.security.core.domain.entity;
  exports com.sitepark.ies.security.core.domain.exception;
  exports com.sitepark.ies.security.core.port;
  exports com.sitepark.ies.security.core.api;

  requires org.apache.logging.log4j;
  requires jakarta.inject;
  requires com.fasterxml.jackson.annotation;
  requires com.fasterxml.jackson.databind;
  requires com.fasterxml.jackson.datatype.jdk8;
  requires com.fasterxml.jackson.datatype.jsr310;
  requires com.github.spotbugs.annotations;
  requires com.sitepark.ies.sharedkernel;

  opens com.sitepark.ies.security.core.port;
  opens com.sitepark.ies.security.core.domain.entity;
}
