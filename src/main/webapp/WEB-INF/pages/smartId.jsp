<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<%@ page contentType="text/html; charset=UTF-8"%>

<form:form method="post" id="smartIdLoginForm" commandName="${commandName}" htmlEscape="true">

	<input type="hidden" name="lt" value="${loginTicket}" />
	<input type="hidden" name="execution" value="${flowExecutionKey}" />
	<input type="hidden" name="_eventId" value="submitSmartId" />
	
	<c:choose>
		<c:when test="${not empty param.TARGET}">
			<!-- "TARGET" is for SAML11 and "service" is for CAS20 protocol -->
			<input type="hidden" name="TARGET" value="<c:out value="${param.TARGET}" />" />
		</c:when>
		<c:otherwise>
			<input type="hidden" name="service" value="<c:out value="${param.service}" />" />
		</c:otherwise>
	</c:choose>
	<input type="hidden" name="renew" value="${param.renew}" />
	<input type="hidden" name="gateway" value="${param.gateway}" />

</form:form>
<div class="smart-id">
	<div class="control">
		<!-- Various messages -->
		<div id="smartId_message" style="display: none;">
			<input id="smartIdCancel" type="button" class="btn btn-primary"
				value="<spring:message code="login.smartid.label.cancelbutton" />"
				onclick="cancelSmartIdAuth()" />
			<p id="sIdMessageText"></p>
			<p id="sIdAuthInfo"><spring:message code="login.smartid.auth.info" /></p>
			<p id="sIdMessageTextError" style="display: none; margin-bottom: 1.25rem;"><spring:message code="login.smartid.error.failed" /></p>
		</div>

		<div id="smartId_actions">
		   <p><img src="<c:url value="/resources/assets/imgs/Smart-ID_login_btn.png" />" width="125"></p>
		   <ul>
		      <li><spring:message code="project.smartid.info" /></li>
		   </ul>
		   <div class="form-group-md">
		   	  <p id="sIdNumberRequired" style="display: none;">
		   	  	<spring:message code="login.smartid.rm.error.canContainOnlyDigits" />
		   	  </p>
		      <input type="text" id="identityCode" name="identityCode" class="form-control" tabindex="2" placeholder="<spring:message code="project.smartid.placeholder" />">
		   </div>
		   <button 
		   		id="smartIdButton" 
		   		data-messageAfterClick="<spring:message code="login.smartid.startingSession" />" 
		   		type="submit" 
		   		class="btn btn-primary"
		   		tabindex="3">
		   		<spring:message code="project.login.via.smartid" />
		   	</button>
		</div>
	</div>
</div>
<script type="text/javascript" src="${pageContext.request.contextPath}/resources/js/jquery.min.js"></script>
<script type="text/javascript" src="${pageContext.request.contextPath}/resources/js/smartId.js"></script>
