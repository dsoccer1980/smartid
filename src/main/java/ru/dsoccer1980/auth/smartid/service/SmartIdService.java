package ru.dsoccer1980.auth.smartid.service;

import ru.dsoccer1980.auth.smartid.model.SmartIdAuth;
import ee.sk.smartid.exception.SmartIdException;

public interface SmartIdService {

	SmartIdAuth createSmartIdAuth(String identityCode);
	
	void authenticate(SmartIdAuth smartIdAuth) throws SmartIdException;
	
}
