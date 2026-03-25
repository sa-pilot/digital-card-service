package io.mosip.digitalcard.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.biometrics.util.ConvertRequestDto;
import io.mosip.biometrics.util.face.FaceDecoder;
import io.mosip.digitalcard.constant.ApiName;
import io.mosip.digitalcard.constant.DigitalCardConstants;
import io.mosip.digitalcard.constant.DigitalCardServiceErrorCodes;
import io.mosip.digitalcard.constant.PDFGeneratorExceptionCodeConstant;
import io.mosip.digitalcard.dto.PDFSignatureRequestDto;
import io.mosip.digitalcard.dto.SignatureResponseDto;
import io.mosip.digitalcard.exception.DigitalCardServiceException;
import io.mosip.digitalcard.repositories.DigitalCardTransactionRepository;
import io.mosip.digitalcard.service.CardGeneratorService;
import io.mosip.digitalcard.util.*;
import io.mosip.kernel.biometrics.spi.CbeffUtil;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.pdfgenerator.exception.PDFGeneratorException;
import io.mosip.kernel.core.pdfgenerator.spi.PDFGenerator;
import io.mosip.kernel.core.qrcodegenerator.exception.QrcodeGenerationException;
import io.mosip.kernel.core.qrcodegenerator.spi.QrCodeGenerator;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.qrcode.generator.zxing.constant.QrVersion;
import io.mosip.vercred.CredentialsVerifier;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class PDFCardServiceImpl implements CardGeneratorService {


	/** The PDFServiceImpl logger. */
	Logger logger = DigitalCardRepoLogger.getLogger(PDFCardServiceImpl.class);

	private static final String DATETIME_PATTERN = "mosip.digitalcard.service.datetime.pattern";

	/** The Constant FILE_SEPARATOR. */
	public static final String FILE_SEPARATOR = File.separator;

	/** The Constant VALUE. */
	private static final String VALUE = "value";

	/** The Constant FACE. */
	private static final String FACE = "Face";

	/** The Constant APPLICANT_PHOTO. */
	private static final String APPLICANT_PHOTO = "ApplicantPhoto";

	/** The Constant QRCODE. */
	private static final String QRCODE = "QrCode";

	@Autowired
	private RestClient restApiClient;

	/** The pdf generator. */
	@Autowired
	private PDFGenerator pdfGenerator;

	/** The template generator. */
	@Autowired
	private TemplateGenerator templateGenerator;

	/** The utilities. */
	@Autowired
	private Utility utility;

	/** The qr code generator. */
	@Autowired
	private QrCodeGenerator<QrVersion> qrCodeGenerator;

	/** The cbeffutil. */
	@Autowired
	private CbeffUtil cbeffutil;

	/** The env. */
	@Autowired
	private Environment env;

	@Autowired
	DigitalCardTransactionRepository digitalCardTransactionRepository;

	@Autowired
	private CredentialsVerifier credentialsVerifier;

	@Value("${mosip.digitalcard.service.uincard.lowerleftx}")
	private int lowerLeftX;

	@Value("${mosip.digitalcard.service.uincard.lowerlefty}")
	private int lowerLeftY;

	@Value("${mosip.digitalcard.service.uincard.upperrightx}")
	private int upperRightX;

	@Value("${mosip.digitalcard.service.uincard.upperrighty}")
	private int upperRightY;

	@Value("${mosip.digitalcard.service.uincard.signature.reason}")
	private String reason;

	@Value("${mosip.digitalcard.uin.card.default.templateTypeCode:RPR_UIN_CARD_TEMPLATE}")
	private String defaultTemplateTypeCode;

	@Value("${mosip.print.service.uincard.signature.required:true}")
	private boolean isSignatureRequired;
	@Autowired
	private ObjectMapper objectMapper;

	public PDFCardServiceImpl() {
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.digitalcard.service.PDFService#
	 */
	public byte[] generateCard(org.json.JSONObject decryptedCredentialJson, String credentialType,
							   String password, Map<String, Object> attributes, String templateLang) throws Exception {
		logger.debug("PDFServiceImpl::getDocuments()::entry");
		boolean isPhotoSet=false;
		String individualBio = null;
		String templateTypeCode = defaultTemplateTypeCode;
		byte[] pdfbytes = null;
		try {
			if(decryptedCredentialJson.has("biometrics")){
				individualBio = decryptedCredentialJson.getString("biometrics");
				String individualBiometric = new String(individualBio);
				isPhotoSet = setApplicantPhoto(individualBiometric, attributes);
				attributes.put("isPhotoSet",isPhotoSet);
			}
			if(attributes.containsKey(DigitalCardConstants.TEMPLATE_TYPE_CODE)) {
				templateTypeCode = attributes.get(DigitalCardConstants.TEMPLATE_TYPE_CODE).toString();
			}
			if (credentialType.equalsIgnoreCase("qrcode")) {
				boolean isQRcodeSet = setQrCode(decryptedCredentialJson.toString(), attributes,isPhotoSet);
				InputStream uinArtifact = templateGenerator.getTemplate(templateTypeCode, attributes, templateLang);
				pdfbytes = generateUinCard(uinArtifact, password);
			} else {
				if (!isPhotoSet) {
					logger.debug(DigitalCardServiceErrorCodes.APPLICANT_PHOTO_NOT_SET.name());
				}
				boolean isQRcodeSet = setQrCode(decryptedCredentialJson.toString(), attributes,isPhotoSet);
				if (!isQRcodeSet) {
					logger.debug(DigitalCardServiceErrorCodes.QRCODE_NOT_SET.name());
				}
				logger.info("Attributes:{}", JSONObject.toJSONString(attributes));
				// getting template and placing original valuespng
				InputStream uinArtifact = templateGenerator.getTemplate(templateTypeCode, attributes, templateLang);
				if (uinArtifact == null) {
					logger.error(DigitalCardServiceErrorCodes.TEM_PROCESSING_FAILURE.name());
					throw new DigitalCardServiceException(
							DigitalCardServiceErrorCodes.TEM_PROCESSING_FAILURE.getErrorCode(),DigitalCardServiceErrorCodes.TEM_PROCESSING_FAILURE.getErrorMessage());
				}
				pdfbytes = generateUinCard(uinArtifact, password);
			}

		}

		catch (QrcodeGenerationException e) {
			logger.error(DigitalCardServiceErrorCodes.QRCODE_NOT_GENERATED.getErrorMessage(), e);
			throw e;
		}  catch (PDFGeneratorException e) {
			logger.error(DigitalCardServiceErrorCodes.PDF_NOT_GENERATED.getErrorMessage() ,e);
			throw e;
		}catch (JsonParseException | JsonMappingException e) {
			logger.error(DigitalCardServiceErrorCodes.ATTRIBUTE_NOT_SET.getErrorMessage() ,e);
			throw e;
		} catch (Exception e) {
			logger.error(PDFGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorMessage() ,e);
			throw e;
		}
		logger.debug("PDFServiceImpl::getDocuments()::exit");
		return pdfbytes;
	}


	/**
	 * Sets the qr code.
	 *
	 * @param attributes   the attributes
	 * @return true, if successful
	 * @throws QrcodeGenerationException                          the qrcode
	 *                                                            generation
	 *                                                            exception
	 * @throws IOException                                        Signals that an
	 *                                                            I/O exception has
	 *                                                            occurred.
	 * @throws QrcodeGenerationException
	 */
	private boolean setQrCode(String qrString, Map<String, Object> attributes,boolean isPhotoSet)
			throws IOException, QrcodeGenerationException {
		boolean isQRCodeSet = false;
		JSONObject qrJsonObj = objectMapper.readValue(qrString, JSONObject.class);
		if(isPhotoSet) {
			qrJsonObj.remove("biometrics");
		}
		byte[] qrCodeBytes = qrCodeGenerator.generateQrCode(qrJsonObj.toString(), QrVersion.V30);
		if (qrCodeBytes != null) {
			String imageString = Base64.encodeBase64String(qrCodeBytes);
			attributes.put(QRCODE, "data:image/png;base64," + imageString);
			isQRCodeSet = true;
		}

		return isQRCodeSet;
	}

	/**
	 * Sets the applicant photo.
	 *
	 *            the response
	 * @param attributes
	 *            the attributes
	 * @return true, if successful
	 * @throws Exception
	 *             the exception
	 */
	private boolean setApplicantPhoto(String individualBio, Map<String, Object> attributes) throws Exception {
		ConvertRequestDto convertRequestDto = new ConvertRequestDto();
		String value = individualBio;
		boolean isPhotoSet = false;

		if (value != null) {
			CbeffToBiometricUtil util = new CbeffToBiometricUtil(cbeffutil);
			List<String> subtype = new ArrayList<>();
			byte[] photoByte = util.getImageBytes(value, FACE, subtype);
			convertRequestDto.setVersion("ISO19794_5_2011");
			convertRequestDto.setInputBytes(photoByte);
			if (photoByte != null) {
				byte[] data = FaceDecoder.convertFaceISOToImageBytes(convertRequestDto);
				String encodedData = StringUtils.newStringUtf8(Base64.encodeBase64(data, false));
				attributes.put(APPLICANT_PHOTO, "data:image/png;base64," + encodedData);
				isPhotoSet = true;
			}
		}
		return isPhotoSet;
	}

	private byte[] generateUinCard(InputStream in, String password) {
		logger.debug("UinCardGeneratorImpl::generateUinCard()::entry");
		byte[] pdfSignatured=null;
		ByteArrayOutputStream out = null;
		try {
			out = (ByteArrayOutputStream) pdfGenerator.generate(in);
			logger.info("Signature required inside pdf " + isSignatureRequired);
			if(isSignatureRequired){
			PDFSignatureRequestDto request = new PDFSignatureRequestDto(lowerLeftX, lowerLeftY, upperRightX,
					upperRightY, reason, 1, password);
			request.setApplicationId("KERNEL");
			request.setReferenceId("SIGN");
			request.setData(Base64.encodeBase64String(out.toByteArray()));
			DateTimeFormatter format = DateTimeFormatter.ofPattern(env.getProperty(DATETIME_PATTERN));
			LocalDateTime localdatetime = LocalDateTime
					.parse(DateUtils.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)), format);

			request.setTimeStamp(DateUtils.getUTCCurrentDateTimeString());
			RequestWrapper<PDFSignatureRequestDto> requestWrapper = new RequestWrapper<>();

			requestWrapper.setRequest(request);
			requestWrapper.setRequesttime(localdatetime);
			ResponseWrapper<?> responseWrapper;
			SignatureResponseDto signatureResponseDto;

			responseWrapper= restApiClient.postApi(ApiName.PDFSIGN, null, "",""
					, MediaType.APPLICATION_JSON,requestWrapper, ResponseWrapper.class);


			if (responseWrapper.getErrors() != null && !responseWrapper.getErrors().isEmpty()) {
				ServiceError error = responseWrapper.getErrors().get(0);
				throw new DigitalCardServiceException(error.getMessage());
			}
			signatureResponseDto = objectMapper.readValue(objectMapper.writeValueAsString(responseWrapper.getResponse()),
					SignatureResponseDto.class);

			pdfSignatured = Base64.decodeBase64(signatureResponseDto.getData());

			} else {
				pdfSignatured = out.toByteArray();
			}
		} catch (Exception e) {
			logger.error(io.mosip.kernel.pdfgenerator.itext.constant.PDFGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorMessage(),e.getMessage()
					+ ExceptionUtils.getStackTrace(e));
		}
		logger.debug("UinCardGeneratorImpl::generateUinCard()::exit");

		return pdfSignatured;
	}
}
	
