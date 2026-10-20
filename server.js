const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Resend } = require('resend');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Resend if API key is provided
const resendApiKey = process.env.RESEND_API_KEY;
const resend = resendApiKey ? new Resend(resendApiKey) : null;

// Security Middleware (adjusted CSP to allow Tailwind, Google Fonts, Lucide icons, and Maps)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://unpkg.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https://images.unsplash.com", "https://www.google.com"],
        frameSrc: ["https://www.google.com"],
      },
    },
  })
);

app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting for appointment submissions to prevent abuse
const appointmentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: { success: false, error: 'Too many appointment requests from this IP. Please try again later or call 012 643 1191.' }
});

app.use('/api/submit-appointment', appointmentLimiter);

// Serve static files from root directory
app.use(express.static(path.join(__dirname)));

// Helper function to sanitize user input against HTML injection
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// API Endpoint for Appointment Submissions
app.post('/api/submit-appointment', async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      phone,
      email,
      service,
      isFirstVisit,
      ageRange,
      childFullName,
      relationshipToChild,
      relationshipOtherText,
      notes
    } = req.body;

    // Server-side validation
    if (!firstName || !lastName || !phone || !email || !service || !isFirstVisit || !ageRange) {
      return res.status(400).json({ success: false, error: 'Please fill in all required appointment fields.' });
    }

    // Basic email format check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: 'Please provide a valid email address.' });
    }

    // Check if Resend is configured
    if (!resend) {
      console.error('RESEND_API_KEY is missing in environment variables.');
      return res.status(500).json({ 
        success: false, 
        error: 'Email service is not fully configured on the server. Please contact the practice directly at 012 643 1191.' 
      });
    }

    // Construct clean data objects
    const cleanFirstName = escapeHtml(firstName);
    const cleanLastName = escapeHtml(lastName);
    const cleanPhone = escapeHtml(phone);
    const cleanEmail = escapeHtml(email);
    const cleanService = escapeHtml(service);
    const cleanIsFirstVisit = escapeHtml(isFirstVisit);
    const cleanAgeRange = escapeHtml(ageRange);
    const cleanChildName = escapeHtml(childFullName || 'Not provided');
    const cleanRelationship = escapeHtml(relationshipToChild || 'Not provided');
    const cleanOtherRel = relationshipOtherText ? ` (${escapeHtml(relationshipOtherText)})` : '';
    const cleanNotes = escapeHtml(notes || 'None provided');

    const emailSubject = `New Appointment Request — Protea Care Medical (${cleanFirstName} ${cleanLastName})`;

    const emailHtmlBody = `
      <div style="font-family: Arial, sans-serif; color: #000; line-height: 1.6; max-width: 600px; margin: 0 auto; border: 1px solid #e5e7eb; padding: 24px;">
        <h2 style="color: #131F6B; border-bottom: 2px solid #EDE882; padding-bottom: 12px; margin-top: 0; font-size: 18px;">
          PROTEA CARE MEDICAL DR M KAZADI NEW APPOINTMENT REQUEST
        </h2>
        
        <h3 style="color: #131F6B; font-size: 14px; text-transform: uppercase; margin-top: 20px;">Patient Details</h3>
        <p style="margin: 4px 0;"><strong>First Name:</strong> ${cleanFirstName}</p>
        <p style="margin: 4px 0;"><strong>Surname:</strong> ${cleanLastName}</p>
        <p style="margin: 4px 0;"><strong>Contact Number:</strong> ${cleanPhone}</p>
        <p style="margin: 4px 0;"><strong>Email Address:</strong> ${cleanEmail}</p>

        ${ageRange !== '18+ years' ? `
        <h3 style="color: #131F6B; font-size: 14px; text-transform: uppercase; margin-top: 20px;">Under-18 Patient Details</h3>
        <p style="margin: 4px 0;"><strong>Child's Full Name:</strong> ${cleanChildName}</p>
        <p style="margin: 4px 0;"><strong>Relationship to Child:</strong> ${cleanRelationship}${cleanOtherRel}</p>
        ` : ''}

        <h3 style="color: #131F6B; font-size: 14px; text-transform: uppercase; margin-top: 20px;">Appointment Details</h3>
        <p style="margin: 4px 0;"><strong>Service Desired:</strong> ${cleanService}</p>
        <p style="margin: 4px 0;"><strong>First Visit:</strong> ${cleanIsFirstVisit}</p>
        <p style="margin: 4px 0;"><strong>Patient Age Range:</strong> ${cleanAgeRange}</p>

        <h3 style="color: #131F6B; font-size: 14px; text-transform: uppercase; margin-top: 20px;">Additional Notes</h3>
        <p style="margin: 4px 0; background: #f9fafb; padding: 12px; border-left: 4px solid #131F6B;">${cleanNotes}</p>

        <h3 style="color: #131F6B; font-size: 14px; text-transform: uppercase; margin-top: 20px;">Submission Information</h3>
        <p style="margin: 4px 0;"><strong>Request Status:</strong> Awaiting confirmation</p>
        <p style="margin: 12px 0 0 0; font-size: 11px; color: #6b7280; font-style: italic;">
          This is an appointment request and must not be represented as a confirmed appointment.
        </p>
      </div>
    `;

    const emailTextBody = `
PROTEA CARE MEDICAL DR M KAZADI NEW APPOINTMENT REQUEST

PATIENT DETAILS
First Name: ${firstName}
Surname: ${lastName}
Contact Number: ${phone}
Email Address: ${email}
${ageRange !== '18+ years' ? `\nUNDER-18 DETAILS\nChild's Full Name: ${childFullName || 'Not provided'}\nRelationship: ${relationshipToChild \vert{}\vert{} 'Not provided'}${relationshipOtherText ? ` (${relationshipOtherText})` : ''}\n` : ''}
APPOINTMENT DETAILS
Service Desired: ${service}
First Visit: ${isFirstVisit}
Patient Age Range: ${ageRange}

ADDITIONAL NOTES / PREFERRED TIME
${notes || 'None provided'}

SUBMISSION INFORMATION
Request Status: Awaiting confirmation
This is an appointment request and must not be represented as a confirmed appointment.
    `.trim();

    // Send email via Resend to proteacaremedical@gmail.com
    const senderEmail = process.env.RESEND_FROM_EMAIL || 'Protea Care Medical <onboarding@resend.dev>';

    const data = await resend.emails.send({
      from: senderEmail,
      to: ['proteacaremedical@gmail.com'],
      replyTo: cleanEmail,
      subject: emailSubject,
      html: emailHtmlBody,
      text: emailTextBody
    });

    return res.status(200).json({ success: true, data });
  } catch (error) {
    console.error('Email delivery error:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'We could not submit your appointment request at this time. Please try again or contact our practice directly at 012 643 1191.' 
    });
  }
});

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Protea Care Medical server running on port ${PORT}`);
});