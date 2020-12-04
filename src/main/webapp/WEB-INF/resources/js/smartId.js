SmartIdStatus = {
		cancelled: false
};

$(function() {
	SmartIdStatus.cancelled=false;
	
	$('#smartIdButton').click(function() {
		var identityCode = $('#identityCode').val();
		
		if (identityCode) {
			identityCode = jQuery.trim(identityCode).replace(/\s+/g, '');
		}
		
		if (!identityCode || !$.isNumeric(identityCode)){
			$('#sIdNumberRequired').show();
		}
		else {
			$('#sIdNumberRequired').hide();
			$("#sIdMessageTextError").hide();
			$('#sIdAuthInfo').show();
			$('#smartIdCancel').show();
			startSmartIdAuth($('#smartIdButton').attr('data-messageAfterClick'));
		}
		
		return false;
	});
});



function hideSmartIdMessage() {
	$('#smartId_message').hide();
	$('#smartId_actions').show();
}
function showSmartIdMessage(content) {
	if (content!==undefined) {
		var dialogContainer = $('#smartId_message');
		dialogContainer.find('#sIdMessageText').html(content);
		//Make sure that message is visible
		dialogContainer.show();
		$('#sIdMessageText').show();
		$('#sIdAuthInfo').show();
		$('#smartId_actions').hide();
	}
}

function cancelSmartIdAuth() {
	SmartIdStatus.cancelled=true;
	hideSmartIdMessage();
}

function startSmartIdAuth(initialMsg) {
	SmartIdStatus.cancelled = false;
	
	showSmartIdMessage(initialMsg);

	$.ajax({
		type : "POST",
		url : "smartIdAuth",
		data : {
		action : "sid_login",
			identityCode : $("#identityCode").val()
		},
		success : smartIdStartAuthenticationResponse,
		error : smartIdError,
		dataType : "json",
		cache : false,
		global : false
	});

	return;
}

function smartIdStartAuthenticationResponse(data, textStatus, XMLHttpRequest) {
	if (SmartIdStatus.cancelled) {
		SmartIdStatus.cancelled=false;
		return;
	}
	showSmartIdMessage(data.message);

	var attemptDelay = data.attemptDelay;
	
	if (data.startStatusCheck) {
		setTimeout(function() {
			$.ajax({
				type : "POST",
				url : "smartIdAuth",
				data : {
				action : "sid_authenticate",
					identityCode : $("#identityCode").val(),
					sessionCode : data.sessionCode
				},
				success : smartIdStartAuthenticationResponse,
				error : smartIdError,
				dataType : "json",
				cache : false,
				global : false
			});
		}, attemptDelay * 1000);
	} else if (data.doCheckCertificate) {
		document.forms['smartIdLoginForm'].submit();
	}
}

function smartIdError(event, request, settings) {
	$('#smartIdCancel').hide();
	$('#sIdMessageText').hide();
	$('#sIdAuthInfo').hide();
	$('#sIdMessageTextError').show();
	$('#smartId_message').show();
	$('#smartId_actions').show();
}