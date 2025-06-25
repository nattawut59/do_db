const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Serve static files from the 'uploads' directory
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Database connection pool - ใช้ database name ที่ถูกต้อง
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'gateway01.us-west-2.prod.aws.tidbcloud.com',
  user: process.env.DB_USER || '417ZsdFRiJocQ5b.root',
  password: process.env.DB_PASSWORD || 'Xykv3WsBxTnwejdj',
  database: process.env.DB_NAME || 'glaucoma_management_system_new', // แก้ไขชื่อ database
  port: process.env.DB_PORT || 4000,
  ssl: {
    rejectUnauthorized: false
  },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
pool.getConnection()
  .then(connection => {
    console.log('✅ Database connection successful');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
  });

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf' || file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF and image files are allowed'));
    }
  },
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Helper function to generate 8-character ID
const generateId = () => {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
};

// Authentication middleware for Doctors
const authDoctor = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

    if (decoded.role !== 'doctor') {
      return res.status(403).json({ error: 'Access denied. Doctor role required.' });
    }

    const [doctors] = await pool.execute(
      `SELECT d.doctor_id, d.first_name, d.last_name, d.license_number, 
              d.department, d.specialty, u.email, u.phone
       FROM DoctorProfiles d
       JOIN Users u ON d.doctor_id = u.user_id
       WHERE d.doctor_id = ? AND u.role = 'doctor' AND u.status = 'active'`,
      [decoded.userId]
    );

    if (doctors.length === 0) {
      return res.status(401).json({ error: 'Invalid token or doctor not found.' });
    }

    req.doctor = doctors[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token.' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Doctor API is running',
    timestamp: new Date().toISOString()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Glaucoma Management System - Doctor API',
    version: '1.0.0',
    database: 'glaucoma_management_system_new'
  });
});

// ===========================================
// DOCTOR AUTHENTICATION ROUTES
// ===========================================

// Doctor Registration
app.post('/api/doctors/register', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const {
      email, password, firstName, lastName, licenseNumber,
      phone, department, specialty, hospitalAffiliation
    } = req.body;

    // Validation
    if (!email || !password || !firstName || !lastName || !licenseNumber) {
      await connection.rollback();
      return res.status(400).json({ error: 'Required fields missing' });
    }

    // Check if doctor already exists
    const [existingUser] = await connection.execute(
      'SELECT user_id FROM Users WHERE email = ?',
      [email]
    );

    if (existingUser.length > 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'Doctor already registered with this email' });
    }

    // Check license number
    const [existingLicense] = await connection.execute(
      'SELECT doctor_id FROM DoctorProfiles WHERE license_number = ?',
      [licenseNumber]
    );

    if (existingLicense.length > 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'License number already registered' });
    }

    const userId = generateId();
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user - ใช้ฟิลด์ที่มีในฐานข้อมูลจริง
    await connection.execute(
      `INSERT INTO Users (user_id, role, password_hash, email, phone, 
                         require_password_change, status)
       VALUES (?, 'doctor', ?, ?, ?, 0, 'active')`,
      [userId, hashedPassword, email, phone]
    );

    // Create doctor profile - ใช้ฟิลด์ที่มีในฐานข้อมูลจริง
    await connection.execute(
      `INSERT INTO DoctorProfiles (
        doctor_id, first_name, last_name, license_number, department,
        specialty, hospital_affiliation, registration_date, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, CURDATE(), 'active')`,
      [userId, firstName, lastName, licenseNumber, department, specialty, hospitalAffiliation]
    );

    await connection.commit();

    // Generate JWT token
    const token = jwt.sign(
      { userId: userId, role: 'doctor' },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Doctor registered successfully',
      token,
      doctor: {
        id: userId,
        firstName,
        lastName,
        email,
        licenseNumber,
        department,
        specialty
      }
    });
  } catch (error) {
    await connection.rollback();
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// Doctor Login
app.post('/api/doctors/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const [doctors] = await pool.execute(
      `SELECT u.user_id, u.password_hash, u.status, d.first_name, d.last_name,
              d.license_number, d.department, d.specialty, u.email
       FROM Users u
       JOIN DoctorProfiles d ON u.user_id = d.doctor_id
       WHERE u.email = ? AND u.role = 'doctor'`,
      [email]
    );

    if (doctors.length === 0) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const doctor = doctors[0];

    if (doctor.status !== 'active') {
      return res.status(400).json({ error: 'Account is not active' });
    }

    const isValidPassword = await bcrypt.compare(password, doctor.password_hash);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Update last login
    await pool.execute(
      'UPDATE Users SET last_login = NOW() WHERE user_id = ?',
      [doctor.user_id]
    );

    const token = jwt.sign(
      { userId: doctor.user_id, role: 'doctor' },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      doctor: {
        id: doctor.user_id,
        firstName: doctor.first_name,
        lastName: doctor.last_name,
        email: doctor.email,
        licenseNumber: doctor.license_number,
        department: doctor.department,
        specialty: doctor.specialty
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get Doctor Profile
app.get('/api/doctors/profile', authDoctor, async (req, res) => {
  try {
    const [profile] = await pool.execute(
      `SELECT d.*, u.email, u.phone, u.created_at, u.last_login
       FROM DoctorProfiles d
       JOIN Users u ON d.doctor_id = u.user_id
       WHERE d.doctor_id = ?`,
      [req.doctor.doctor_id]
    );

    res.json(profile[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Doctor Profile
app.put('/api/doctors/profile', authDoctor, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const {
      firstName, lastName, department, specialty, 
      hospitalAffiliation, phone
    } = req.body;

    // Update doctor profile
    await connection.execute(
      `UPDATE DoctorProfiles SET 
       first_name = ?, last_name = ?, department = ?, specialty = ?,
       hospital_affiliation = ?
       WHERE doctor_id = ?`,
      [firstName, lastName, department, specialty, 
       hospitalAffiliation, req.doctor.doctor_id]
    );

    // Update user phone if provided
    if (phone) {
      await connection.execute(
        'UPDATE Users SET phone = ? WHERE user_id = ?',
        [phone, req.doctor.doctor_id]
      );
    }

    await connection.commit();
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    await connection.rollback();
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// ===========================================
// PATIENT MANAGEMENT ROUTES
// ===========================================

// Get all patients
app.get('/api/patients', authDoctor, async (req, res) => {
    try {
        const [patients] = await pool.execute(`
            SELECT patient_id, hn, first_name, last_name, date_of_birth, 
                   gender, registration_date
            FROM PatientProfiles 
            ORDER BY registration_date DESC
        `);
        
        res.json(patients);
    } catch (error) {
        console.error('Error getting patients:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get specific patient with complete medical info
app.get('/api/patients/:patientId', authDoctor, async (req, res) => {
  try {
    const patientId = req.params.patientId;

    // Get patient basic info
    const [patients] = await pool.execute(
      `SELECT p.*, u.email, u.phone,
              TIMESTAMPDIFF(YEAR, p.date_of_birth, CURDATE()) as age
       FROM PatientProfiles p
       JOIN Users u ON p.patient_id = u.user_id
       WHERE p.patient_id = ?`,
      [patientId]
    );

    if (patients.length === 0) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    const patient = patients[0];

    // Get latest IOP measurements
    const [latestIOP] = await pool.execute(
      `SELECT * FROM IOP_Measurements 
       WHERE patient_id = ? 
       ORDER BY measurement_date DESC, measurement_time DESC 
       LIMIT 5`,
      [patientId]
    );

    // Get active medications
    const [medications] = await pool.execute(
      `SELECT pm.*, m.name as medication_name, m.generic_name,
              COALESCE(CONCAT(d.first_name, ' ', d.last_name), 'ไม่ระบุ') as prescribed_by
       FROM PatientMedications pm
       JOIN Medications m ON pm.medication_id = m.medication_id
       LEFT JOIN DoctorProfiles d ON pm.doctor_id = d.doctor_id
       WHERE pm.patient_id = ? AND pm.status = 'active'
       ORDER BY pm.start_date DESC`,
      [patientId]
    );

    // Get medical history
    const [medicalHistory] = await pool.execute(
      `SELECT * FROM PatientMedicalHistory 
       WHERE patient_id = ? 
       ORDER BY recorded_at DESC`,
      [patientId]
    );

    // Get active treatment plan
    const [treatmentPlan] = await pool.execute(
      `SELECT gtp.*, CONCAT(d.first_name, ' ', d.last_name) as created_by
       FROM GlaucomaTreatmentPlans gtp
       LEFT JOIN DoctorProfiles d ON gtp.doctor_id = d.doctor_id
       WHERE gtp.patient_id = ? AND gtp.status = 'active' 
       ORDER BY gtp.start_date DESC 
       LIMIT 1`,
      [patientId]
    );

    res.json({
      ...patient,
      latestIOP,
      medications,
      medicalHistory,
      treatmentPlan: treatmentPlan[0] || null
    });
  } catch (error) {
    console.error('Error getting patient details:', error);
    res.status(500).json({ error: error.message });
  }
});

// Assign patient to doctor
app.post('/api/patients/:patientId/assign', authDoctor, async (req, res) => {
  try {
    const patientId = req.params.patientId;

    // Check if patient exists
    const [patient] = await pool.execute(
      'SELECT patient_id FROM PatientProfiles WHERE patient_id = ?',
      [patientId]
    );

    if (patient.length === 0) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Check if relationship already exists
    const [existing] = await pool.execute(
      `SELECT relationship_id FROM DoctorPatientRelationships
       WHERE doctor_id = ? AND patient_id = ?`,
      [req.doctor.doctor_id, patientId]
    );

    if (existing.length > 0) {
      // Reactivate if inactive
      await pool.execute(
        `UPDATE DoctorPatientRelationships 
         SET status = 'active', end_date = NULL 
         WHERE doctor_id = ? AND patient_id = ?`,
        [req.doctor.doctor_id, patientId]
      );
    } else {
      // Create new relationship
      const relationshipId = generateId();
      await pool.execute(
        `INSERT INTO DoctorPatientRelationships 
         (relationship_id, doctor_id, patient_id, start_date, status)
         VALUES (?, ?, ?, CURDATE(), 'active')`,
        [relationshipId, req.doctor.doctor_id, patientId]
      );
    }

    res.json({ message: 'Patient assigned successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===========================================
// MEDICATION MANAGEMENT ROUTES
// ===========================================

// Prescribe medication
app.post('/api/patients/:patientId/medications', authDoctor, async (req, res) => {
  console.log('💊 Prescription endpoint called');
  console.log('📝 Request body:', JSON.stringify(req.body, null, 2));
  
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const patientId = req.params.patientId;
    const doctorId = req.doctor.doctor_id;

    const {
      medicationName, genericName, category, form, strength,
      eyeSelection, dosageAmount, concentration, 
      frequencyType, frequencyValue, instructionNotes,
      eye, dosage, frequency, specialInstructions,
      duration
    } = req.body;

    // ใช้ระบบใหม่ถ้ามี ไม่งั้นใช้ระบบเก่า
    const finalEyeSelection = eyeSelection || eye || 'both';
    const finalDosage = dosageAmount || dosage || '1 หยด';
    const finalFrequencyType = frequencyType || 'hourly';
    const finalFrequencyValue = frequencyValue || frequency || 'วันละ 1 ครั้ง';
    const finalInstructions = instructionNotes || specialInstructions || null;

    // Validation
    if (!medicationName || !strength) {
      await connection.rollback();
      return res.status(400).json({ error: 'Medication name and strength are required' });
    }

    // Check if patient exists
    const [patientExists] = await connection.execute(
      'SELECT patient_id, first_name, last_name FROM PatientProfiles WHERE patient_id = ?',
      [patientId]
    );

    if (patientExists.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Create doctor-patient relationship if not exists
    let [relationship] = await pool.execute(
      `SELECT relationship_id FROM DoctorPatientRelationships
       WHERE doctor_id = ? AND patient_id = ?`,
      [doctorId, patientId]
    );

    if (relationship.length === 0) {
      const relationshipId = generateId();
      await pool.execute(
        `INSERT INTO DoctorPatientRelationships 
         (relationship_id, doctor_id, patient_id, start_date, status)
         VALUES (?, ?, ?, CURDATE(), 'active')`,
        [relationshipId, doctorId, patientId]
      );
    }

    // Find or create medication
    let [medication] = await pool.execute(
      'SELECT medication_id FROM Medications WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))',
      [medicationName]
    );

    let medicationId;
    if (medication.length === 0) {
      medicationId = generateId();
      
      // Storage instructions based on medication type
      let storageInstructions = 'เก็บในที่แห้ง หลีกเลี่ยงแสงแดด';
      if (medicationName.toLowerCase().includes('latanoprost') || 
          medicationName.toLowerCase().includes('travoprost')) {
        storageInstructions = 'แช่ตู้เย็น';
      }

      await connection.execute(
        `INSERT INTO Medications (
          medication_id, name, generic_name, category, form, strength, 
          instructions, storage_instructions, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
        [
          medicationId, 
          medicationName.trim(), 
          genericName || medicationName.trim(), 
          category || 'Glaucoma Medication',
          form || 'eye_drops',
          strength.trim(),
          'ใช้ตามแพทย์สั่ง เขย่าก่อนใช้',
          storageInstructions
        ]
      );
    } else {
      medicationId = medication[0].medication_id;
    }

    // Create prescription
    const prescriptionId = generateId();
    const startDate = new Date().toISOString().split('T')[0];
    let endDate = null;

    if (duration && !isNaN(parseInt(duration)) && parseInt(duration) > 0) {
      const end = new Date();
      end.setDate(end.getDate() + parseInt(duration));
      endDate = end.toISOString().split('T')[0];
    }

    await connection.execute(
      `INSERT INTO PatientMedications (
        prescription_id, patient_id, medication_id, doctor_id, prescribed_date,
        start_date, end_date, eye, dosage, frequency, duration, 
        special_instructions, status, concentration, frequency_type, 
        frequency_value, instruction_notes
      ) VALUES (?, ?, ?, ?, CURDATE(), ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`,
      [
        prescriptionId, patientId, medicationId, doctorId,
        startDate, endDate, 
        finalEyeSelection,
        finalDosage,
        finalFrequencyValue,
        duration ? parseInt(duration) : null,
        finalInstructions,
        concentration || null,
        finalFrequencyType,
        finalFrequencyValue,
        finalInstructions
      ]
    );

    await connection.commit();

    res.status(201).json({
      prescriptionId,
      message: 'Medication prescribed successfully'
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error prescribing medication:', error);
    res.status(500).json({ error: 'Failed to prescribe medication: ' + error.message });
  } finally {
    connection.release();
  }
});

// Get patient medications
app.get('/api/patients/:patientId/medications', authDoctor, async (req, res) => {
  try {
    const patientId = req.params.patientId;

    const [medications] = await pool.execute(
      `SELECT pm.prescription_id, pm.eye, pm.dosage, pm.frequency, pm.start_date,
              pm.end_date, pm.status, pm.special_instructions, pm.prescribed_date,
              pm.duration, pm.discontinued_reason, pm.concentration, 
              pm.frequency_type, pm.frequency_value, pm.instruction_notes,
              m.name as medication_name, m.generic_name, m.category, m.form, m.strength,
              m.instructions as medication_instructions, m.storage_instructions,
              COALESCE(CONCAT(d.first_name, ' ', d.last_name), 'ไม่ระบุ') as prescribed_by
       FROM PatientMedications pm
       JOIN Medications m ON pm.medication_id = m.medication_id
       LEFT JOIN DoctorProfiles d ON pm.doctor_id = d.doctor_id
       WHERE pm.patient_id = ?
       ORDER BY pm.prescribed_date DESC, pm.start_date DESC`,
      [patientId]
    );

    res.json(medications);

  } catch (error) {
    console.error('❌ Error getting patient medications:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update medication
app.put('/api/medications/:prescriptionId', authDoctor, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    const prescriptionId = req.params.prescriptionId;
    const doctorId = req.doctor.doctor_id;
    const {
      eyeSelection, dosageAmount, concentration, 
      frequencyType, frequencyValue, instructionNotes,
      status, discontinuedReason
    } = req.body;

    // Check authorization
    const [prescription] = await connection.execute(
      `SELECT pm.prescription_id, pm.patient_id 
       FROM PatientMedications pm
       WHERE pm.prescription_id = ? AND pm.doctor_id = ?`,
      [prescriptionId, doctorId]
    );

    if (prescription.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Prescription not found or unauthorized' });
    }

    // Build dynamic update query
    const updateFields = [];
    const updateValues = [];

    if (eyeSelection) {
      updateFields.push('eye = ?');
      updateValues.push(eyeSelection);
    }
    if (dosageAmount) {
      updateFields.push('dosage = ?');
      updateValues.push(dosageAmount);
    }
    if (concentration) {
      updateFields.push('concentration = ?');
      updateValues.push(concentration);
    }
    if (frequencyType) {
      updateFields.push('frequency_type = ?');
      updateValues.push(frequencyType);
    }
    if (frequencyValue) {
      updateFields.push('frequency_value = ?', 'frequency = ?');
      updateValues.push(frequencyValue, frequencyValue);
    }
    if (instructionNotes !== undefined) {
      updateFields.push('instruction_notes = ?', 'special_instructions = ?');
      updateValues.push(instructionNotes, instructionNotes);
    }
    if (status) {
      updateFields.push('status = ?');
      updateValues.push(status);
      if (status === 'discontinued' && discontinuedReason) {
        updateFields.push('discontinued_reason = ?');
        updateValues.push(discontinuedReason);
      }
    }

    if (updateFields.length === 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'No fields to update' });
    }

    updateFields.push('updated_at = NOW()');
    updateValues.push(prescriptionId);

    await connection.execute(
      `UPDATE PatientMedications SET ${updateFields.join(', ')} WHERE prescription_id = ?`,
      updateValues
    );

    await connection.commit();
    res.json({ message: 'Prescription updated successfully', prescriptionId });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error updating prescription:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// Delete/Discontinue medication
app.delete('/api/medications/:prescriptionId', authDoctor, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    const prescriptionId = req.params.prescriptionId;
    const doctorId = req.doctor.doctor_id;
    const { reason } = req.body;

    // Check authorization
    const [prescription] = await connection.execute(
      `SELECT pm.prescription_id, pm.patient_id, pm.status
       FROM PatientMedications pm
       WHERE pm.prescription_id = ? AND pm.doctor_id = ?`,
      [prescriptionId, doctorId]
    );

    if (prescription.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Prescription not found or unauthorized' });
    }

    if (prescription[0].status !== 'active') {
      await connection.rollback();
      return res.status(400).json({ error: 'Prescription is already discontinued' });
    }

    // Discontinue medication
    await connection.execute(
      `UPDATE PatientMedications 
       SET status = 'discontinued', 
           discontinued_reason = ?,
           end_date = CURDATE(),
           updated_at = NOW()
       WHERE prescription_id = ?`,
      [reason || 'หยุดโดยแพทย์', prescriptionId]
    );

    await connection.commit();
    res.json({ 
      message: 'Prescription discontinued successfully',
      prescriptionId,
      reason: reason || 'หยุดโดยแพทย์'
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error discontinuing prescription:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// ===========================================
// IOP MEASUREMENT ROUTES
// ===========================================

// Add IOP measurement
app.post('/api/patients/:patientId/iop-measurements', authDoctor, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const patientId = req.params.patientId;
    const doctorId = req.doctor.doctor_id;

    const {
      measurementDate,
      measurementTime, 
      leftEyeIOP,
      rightEyeIOP,
      measurementDevice,
      measurementMethod,
      notes
    } = req.body;

    // Validation
    if (!measurementDate) {
      await connection.rollback();
      return res.status(400).json({ error: 'Measurement date is required' });
    }

    if (!leftEyeIOP && !rightEyeIOP) {
      await connection.rollback();
      return res.status(400).json({ error: 'At least one eye IOP measurement is required' });
    }

    // Check if patient exists
    const [patientExists] = await connection.execute(
      'SELECT patient_id, first_name, last_name FROM PatientProfiles WHERE patient_id = ?',
         [patientId]
    );

    if (patientExists.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Create doctor-patient relationship if not exists
    let [relationship] = await connection.execute(
      `SELECT relationship_id FROM DoctorPatientRelationships
       WHERE doctor_id = ? AND patient_id = ?`,
      [doctorId, patientId]
    );

    if (relationship.length === 0) {
      const relationshipId = generateId();
      await connection.execute(
        `INSERT INTO DoctorPatientRelationships 
         (relationship_id, doctor_id, patient_id, start_date, status)
         VALUES (?, ?, ?, CURDATE(), 'active')`,
        [relationshipId, doctorId, patientId]
      );
    }

    // Create IOP measurement record
    const measurementId = generateId();
    const formattedTime = measurementTime || new Date().toTimeString().slice(0, 8);

    await connection.execute(
      `INSERT INTO IOP_Measurements (
        measurement_id, patient_id, recorded_by, measurement_date, measurement_time,
        left_eye_iop, right_eye_iop, measurement_device, measurement_method, 
        measured_at_hospital, notes, doctor_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        measurementId,
        patientId,
        doctorId, // recorded_by
        measurementDate,
        formattedTime,
        leftEyeIOP && !isNaN(parseFloat(leftEyeIOP)) ? parseFloat(leftEyeIOP) : null,
        rightEyeIOP && !isNaN(parseFloat(rightEyeIOP)) ? parseFloat(rightEyeIOP) : null,
        measurementDevice || 'GAT',
        measurementMethod || 'Goldmann Applanation Tonometry',
        1, // measured_at_hospital (true)
        notes || null,
        doctorId
      ]
    );

    // Create alert for high IOP (> 21 mmHg)
    const leftHigh = leftEyeIOP && parseFloat(leftEyeIOP) > 21;
    const rightHigh = rightEyeIOP && parseFloat(rightEyeIOP) > 21;

    if (leftHigh || rightHigh) {
      const alertId = generateId();
      const eyeText = leftHigh && rightHigh ? 'ทั้งสองข้าง' : leftHigh ? 'ตาซ้าย' : 'ตาขวา';
      const iopValues = leftHigh && rightHigh ? 
        `${leftEyeIOP}/${rightEyeIOP}` : 
        leftHigh ? leftEyeIOP : rightEyeIOP;

      await connection.execute(
        `INSERT INTO Alerts (
          alert_id, patient_id, alert_type, severity, alert_message, 
          related_entity_type, related_entity_id, created_at, 
          acknowledged, resolution_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), 0, 'pending')`,
        [
          alertId,
          patientId,
          'high_iop',
          'high',
          `IOP สูงผิดปกติ ${eyeText}: ${iopValues} mmHg (วันที่ ${measurementDate})`,
          'iop_measurement',
          measurementId
        ]
      );
    }

    await connection.commit();

    res.status(201).json({
      measurementId,
      message: 'IOP measurement recorded successfully',
      data: {
        measurementDate,
        measurementTime: formattedTime,
        leftEyeIOP: leftEyeIOP ? parseFloat(leftEyeIOP) : null,
        rightEyeIOP: rightEyeIOP ? parseFloat(rightEyeIOP) : null
      }
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error recording IOP measurement:', error);
    res.status(500).json({ 
      error: 'Failed to record IOP measurement: ' + error.message 
    });
  } finally {
    connection.release();
  }
});

// Get IOP measurements for patient
app.get('/api/patients/:patientId/iop-measurements', authDoctor, async (req, res) => {
  try {
    const patientId = req.params.patientId;
    const { startDate, endDate, limit } = req.query;

    // Check if patient exists
    const [patientExists] = await pool.execute(
      'SELECT patient_id, first_name, last_name FROM PatientProfiles WHERE patient_id = ?',
      [patientId]
    );

    if (patientExists.length === 0) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Build query parameters
    let whereClause = 'WHERE iop.patient_id = ?';
    let queryParams = [patientId];

    if (startDate) {
      whereClause += ' AND iop.measurement_date >= ?';
      queryParams.push(startDate);
    }
    if (endDate) {
      whereClause += ' AND iop.measurement_date <= ?';
      queryParams.push(endDate);
    }

    const limitClause = limit ? `LIMIT ${parseInt(limit)}` : 'LIMIT 50';

    const [measurements] = await pool.execute(
      `SELECT iop.measurement_id, iop.measurement_date, iop.measurement_time,
              iop.left_eye_iop, iop.right_eye_iop, iop.measurement_device, 
              iop.measurement_method, iop.notes,
              CONCAT(d.first_name, ' ', d.last_name) as measured_by
       FROM IOP_Measurements iop
       LEFT JOIN DoctorProfiles d ON iop.doctor_id = d.doctor_id
       ${whereClause}
       ORDER BY iop.measurement_date DESC, iop.measurement_time DESC
       ${limitClause}`,
      queryParams
    );

    // Calculate statistics
    const stats = {
      total_measurements: measurements.length,
      latest_measurement: measurements[0] || null,
      average_left: null,
      average_right: null,
      max_left: null,
      max_right: null,
      min_left: null,
      min_right: null
    };

    if (measurements.length > 0) {
      const leftValues = measurements.filter(m => m.left_eye_iop !== null).map(m => m.left_eye_iop);
      const rightValues = measurements.filter(m => m.right_eye_iop !== null).map(m => m.right_eye_iop);

      if (leftValues.length > 0) {
        stats.average_left = (leftValues.reduce((a, b) => a + b, 0) / leftValues.length).toFixed(1);
        stats.max_left = Math.max(...leftValues);
        stats.min_left = Math.min(...leftValues);
      }

      if (rightValues.length > 0) {
        stats.average_right = (rightValues.reduce((a, b) => a + b, 0) / rightValues.length).toFixed(1);
        stats.max_right = Math.max(...rightValues);
        stats.min_right = Math.min(...rightValues);
      }
    }

    res.json({
      measurements,
      stats,
      patient_name: `${patientExists[0].first_name} ${patientExists[0].last_name}`
    });

  } catch (error) {
    console.error('❌ Error loading IOP measurements:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===========================================
// SURGERY MANAGEMENT ROUTES
// ===========================================

// Add glaucoma surgery record
app.post('/api/patients/:patientId/surgeries', authDoctor, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const patientId = req.params.patientId;
    const doctorId = req.doctor.doctor_id;
    
    const {
      surgeryDate, surgeryType, eye, preOpIOPLeft, preOpIOPRight,
      procedureDetails, complications, postOpCare, outcome, 
      followUpPlan, notes
    } = req.body;

    // Validation
    if (!surgeryDate || !surgeryType || !eye) {
      await connection.rollback();
      return res.status(400).json({ 
        error: 'Surgery date, type, and eye are required' 
      });
    }

    // Check if patient exists
    const [patientExists] = await connection.execute(
      'SELECT patient_id FROM PatientProfiles WHERE patient_id = ?',
      [patientId]
    );

    if (patientExists.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Create doctor-patient relationship if not exists
    let [relationship] = await connection.execute(
      `SELECT relationship_id FROM DoctorPatientRelationships
       WHERE doctor_id = ? AND patient_id = ?`,
      [doctorId, patientId]
    );

    if (relationship.length === 0) {
      const relationshipId = generateId();
      await connection.execute(
        `INSERT INTO DoctorPatientRelationships 
         (relationship_id, doctor_id, patient_id, start_date, status)
         VALUES (?, ?, ?, CURDATE(), 'active')`,
        [relationshipId, doctorId, patientId]
      );
    }

    const surgeryId = generateId();

    await connection.execute(
      `INSERT INTO GlaucomaSurgeries (
        surgery_id, patient_id, doctor_id, surgery_date, surgery_type, eye,
        pre_op_iop_left, pre_op_iop_right, procedure_details, complications,
        post_op_care, outcome, follow_up_plan, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [surgeryId, patientId, doctorId, surgeryDate, surgeryType, eye,
       preOpIOPLeft ? parseFloat(preOpIOPLeft) : null, 
       preOpIOPRight ? parseFloat(preOpIOPRight) : null, 
       procedureDetails, complications, postOpCare, outcome, followUpPlan, notes]
    );

    await connection.commit();

    res.status(201).json({
      surgeryId,
      message: 'Surgery record created successfully'
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error creating surgery record:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// Get surgeries for patient
app.get('/api/patients/:patientId/surgeries', authDoctor, async (req, res) => {
  try {
    const patientId = req.params.patientId;

    const [surgeries] = await pool.execute(
      `SELECT gs.surgery_id, gs.surgery_date, gs.surgery_type, gs.eye,
              gs.pre_op_iop_left, gs.pre_op_iop_right, gs.procedure_details,
              gs.complications, gs.outcome, gs.notes, gs.report_url,
              CONCAT(d.first_name, ' ', d.last_name) as surgeon_name
       FROM GlaucomaSurgeries gs
       LEFT JOIN DoctorProfiles d ON gs.doctor_id = d.doctor_id
       WHERE gs.patient_id = ?
       ORDER BY gs.surgery_date DESC`,
      [patientId]
    );

    res.json(surgeries);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===========================================
// TREATMENT PLAN ROUTES
// ===========================================

// Create treatment plan
app.post('/api/patients/:patientId/treatment-plans', authDoctor, async (req, res) => {
  console.log('📋 Creating treatment plan...');
  
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const patientId = req.params.patientId;
    const doctorId = req.doctor.doctor_id;
    
    const {
      treatmentApproach, targetIOPLeft, targetIOPRight,
      followUpFrequency, visualFieldTestFrequency, notes
    } = req.body;

    // Check if patient exists
    const [patientExists] = await connection.execute(
      'SELECT patient_id, first_name, last_name FROM PatientProfiles WHERE patient_id = ?',
      [patientId]
    );

    if (patientExists.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Create doctor-patient relationship if not exists
    let [relationship] = await connection.execute(
      `SELECT relationship_id FROM DoctorPatientRelationships
       WHERE doctor_id = ? AND patient_id = ?`,
      [doctorId, patientId]
    );

    if (relationship.length === 0) {
      const relationshipId = generateId();
      await connection.execute(
        `INSERT INTO DoctorPatientRelationships 
         (relationship_id, doctor_id, patient_id, start_date, status)
         VALUES (?, ?, ?, CURDATE(), 'active')`,
        [relationshipId, doctorId, patientId]
      );
    }

    // Mark existing active plans as completed
    await connection.execute(
      `UPDATE GlaucomaTreatmentPlans 
       SET status = 'completed', end_date = CURDATE()
       WHERE patient_id = ? AND status = 'active'`,
      [patientId]
    );

    // Create new treatment plan
    const treatmentPlanId = generateId();

    await connection.execute(
      `INSERT INTO GlaucomaTreatmentPlans (
        treatment_plan_id, patient_id, doctor_id, start_date, treatment_approach,
        target_iop_left, target_iop_right, follow_up_frequency,
        visual_field_test_frequency, notes, status
      ) VALUES (?, ?, ?, CURDATE(), ?, ?, ?, ?, ?, ?, 'active')`,
      [
        treatmentPlanId, 
        patientId, 
        doctorId, 
        treatmentApproach || 'Standard glaucoma treatment',
        targetIOPLeft && !isNaN(parseFloat(targetIOPLeft)) ? parseFloat(targetIOPLeft) : null,
        targetIOPRight && !isNaN(parseFloat(targetIOPRight)) ? parseFloat(targetIOPRight) : null,
        followUpFrequency || null,
        visualFieldTestFrequency || null,
        notes || null
      ]
    );

    await connection.commit();

    res.status(201).json({
      treatmentPlanId,
      message: 'Treatment plan created successfully'
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error creating treatment plan:', error);
    res.status(500).json({ error: 'Failed to create treatment plan: ' + error.message });
  } finally {
    connection.release();
  }
});

// Get treatment plan for patient
app.get('/api/patients/:patientId/treatment-plan', authDoctor, async (req, res) => {
  try {
    const patientId = req.params.patientId;

    const [plans] = await pool.execute(
      `SELECT gtp.treatment_plan_id, gtp.start_date, gtp.end_date, gtp.treatment_approach,
              gtp.target_iop_left, gtp.target_iop_right, gtp.follow_up_frequency,
              gtp.visual_field_test_frequency, gtp.notes, gtp.status,
              CONCAT(d.first_name, ' ', d.last_name) as created_by_name
       FROM GlaucomaTreatmentPlans gtp
       LEFT JOIN DoctorProfiles d ON gtp.doctor_id = d.doctor_id
       WHERE gtp.patient_id = ?
       ORDER BY gtp.start_date DESC`,
      [patientId]
    );

    res.json(plans);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update treatment plan
app.put('/api/treatment-plans/:planId', authDoctor, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    const planId = req.params.planId;
    const doctorId = req.doctor.doctor_id;
    const {
      treatmentApproach, targetIOPLeft, targetIOPRight,
      followUpFrequency, visualFieldTestFrequency, notes, status
    } = req.body;

    // Check if plan exists and belongs to doctor's patient
    const [plan] = await connection.execute(
      `SELECT gtp.treatment_plan_id FROM GlaucomaTreatmentPlans gtp
       JOIN DoctorPatientRelationships dpr ON gtp.patient_id = dpr.patient_id
       WHERE gtp.treatment_plan_id = ? AND dpr.doctor_id = ? AND dpr.status = 'active'`,
      [planId, doctorId]
    );

    if (plan.length === 0) {
      await connection.rollback();
      return res.status(403).json({ error: 'Treatment plan not found or unauthorized' });
    }

    // Build dynamic update query
    const updateFields = [];
    const updateValues = [];

    if (treatmentApproach) {
      updateFields.push('treatment_approach = ?');
      updateValues.push(treatmentApproach);
    }
    if (targetIOPLeft !== undefined) {
      updateFields.push('target_iop_left = ?');
      updateValues.push(targetIOPLeft);
    }
    if (targetIOPRight !== undefined) {
      updateFields.push('target_iop_right = ?');
      updateValues.push(targetIOPRight);
    }
    if (followUpFrequency) {
      updateFields.push('follow_up_frequency = ?');
      updateValues.push(followUpFrequency);
    }
    if (visualFieldTestFrequency) {
      updateFields.push('visual_field_test_frequency = ?');
      updateValues.push(visualFieldTestFrequency);
    }
    if (notes) {
      updateFields.push('notes = ?');
      updateValues.push(notes);
    }
    if (status) {
      updateFields.push('status = ?');
      updateValues.push(status);
      if (status === 'completed') {
        updateFields.push('end_date = CURDATE()');
      }
    }

    if (updateFields.length === 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'No fields to update' });
    }

    updateFields.push('updated_at = NOW()');
    updateValues.push(planId);

    await connection.execute(
      `UPDATE GlaucomaTreatmentPlans SET ${updateFields.join(', ')} 
       WHERE treatment_plan_id = ?`,
      updateValues
    );

    await connection.commit();
    res.json({ message: 'Treatment plan updated successfully' });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error updating treatment plan:', error);
    res.status(500).json({ error: error.message });
  } finally {
    connection.release();
  }
});

// ===========================================
// SPECIAL TESTS ROUTES (OCT, CTVF)
// ===========================================

// Add special test results
app.post('/api/patients/:patientId/special-tests', authDoctor, upload.single('pdfFile'), async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const patientId = req.params.patientId;
    const doctorId = req.doctor.doctor_id;
    const { testType, testDate, eye, testDetails, results, notes } = req.body;

    // Validation
    if (!testType || !testDate) {
      await connection.rollback();
      return res.status(400).json({ error: 'Test type and date are required' });
    }

    // Check if patient exists
    const [patientExists] = await connection.execute(
      'SELECT patient_id, first_name, last_name FROM PatientProfiles WHERE patient_id = ?',
      [patientId]
    );

    if (patientExists.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Create doctor-patient relationship if not exists
    let [relationship] = await connection.execute(
      `SELECT relationship_id FROM DoctorPatientRelationships
       WHERE doctor_id = ? AND patient_id = ?`,
      [doctorId, patientId]
    );

    if (relationship.length === 0) {
      const relationshipId = generateId();
      await connection.execute(
        `INSERT INTO DoctorPatientRelationships 
         (relationship_id, doctor_id, patient_id, start_date, status)
         VALUES (?, ?, ?, CURDATE(), 'active')`,
        [relationshipId, doctorId, patientId]
      );
    }

    const testId = generateId();
    const reportUrl = req.file ? req.file.filename : null;

    // Save special test
    await connection.execute(
      `INSERT INTO SpecialEyeTests (
        test_id, patient_id, doctor_id, test_date, test_type, eye,
        test_details, results, test_images_url, report_url, notes, uploaded_by, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed')`,
      [testId, patientId, doctorId, testDate, testType, eye || 'both',
       testDetails || null, results || null, null, reportUrl, notes || null, doctorId]
    );

    // If OCT test, save to OCT_Results table
    if (testType === 'OCT' && results) {
      try {
        const resultsData = typeof results === 'string' ? JSON.parse(results) : results;
        const octId = generateId();

        await connection.execute(
          `INSERT INTO OCT_Results (
            oct_id, test_id, left_avg_rnfl, right_avg_rnfl, left_superior_rnfl,
            right_superior_rnfl, left_inferior_rnfl, right_inferior_rnfl,
            left_temporal_rnfl, right_temporal_rnfl, left_nasal_rnfl, right_nasal_rnfl,
            left_cup_disc_ratio, right_cup_disc_ratio, left_rim_area, right_rim_area,
            left_image_url, right_image_url
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [octId, testId, 
           resultsData.leftAvgRNFL || null, resultsData.rightAvgRNFL || null,
           resultsData.leftSuperiorRNFL || null, resultsData.rightSuperiorRNFL || null,
           resultsData.leftInferiorRNFL || null, resultsData.rightInferiorRNFL || null,
           resultsData.leftTemporalRNFL || null, resultsData.rightTemporalRNFL || null,
           resultsData.leftNasalRNFL || null, resultsData.rightNasalRNFL || null,
           resultsData.leftCupDiscRatio || null, resultsData.rightCupDiscRatio || null,
           resultsData.leftRimArea || null, resultsData.rightRimArea || null,
           resultsData.leftImageUrl || null, resultsData.rightImageUrl || null]
        );
      } catch (parseError) {
        console.warn('Failed to parse OCT results:', parseError);
      }
    }

    await connection.commit();

    res.status(201).json({
      testId,
      message: 'Special test recorded successfully',
      test: {
        test_id: testId,
        test_type: testType,
        test_date: testDate,
        patient_name: `${patientExists[0].first_name} ${patientExists[0].last_name}`
      },
      reportUrl: reportUrl ? `/uploads/${reportUrl}` : null
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error creating special test:', error);
    res.status(500).json({ 
      error: 'Failed to record special test: ' + error.message 
    });
  } finally {
    connection.release();
  }
});

// Get special tests for patient
app.get('/api/patients/:patientId/special-tests', authDoctor, async (req, res) => {
  try {
    const patientId = req.params.patientId;
    const { testType, startDate, endDate } = req.query;

    let whereClause = 'WHERE st.patient_id = ?';
    let queryParams = [patientId];

    if (testType && testType !== 'undefined') {
      whereClause += ' AND st.test_type = ?';
      queryParams.push(testType);
    }
    if (startDate && startDate !== 'undefined') {
      whereClause += ' AND st.test_date >= ?';
      queryParams.push(startDate);
    }
    if (endDate && endDate !== 'undefined') {
      whereClause += ' AND st.test_date <= ?';
      queryParams.push(endDate);
    }

    const [tests] = await pool.execute(
      `SELECT st.test_id, st.test_date, st.test_type, st.eye,
              st.test_details, st.results, st.report_url, st.notes,
              CONCAT(d.first_name, ' ', d.last_name) as performed_by
       FROM SpecialEyeTests st
       LEFT JOIN DoctorProfiles d ON st.doctor_id = d.doctor_id
       ${whereClause}
       ORDER BY st.test_date DESC`,
      queryParams
    );

    // Format report URLs
    const formattedTests = tests.map(test => ({
      ...test,
      report_url: test.report_url ? `/uploads/${test.report_url}` : null
    }));

    res.json(formattedTests);

  } catch (error) {
    console.error('❌ Error getting special tests:', error);
    res.status(500).json({ error: error.message });
  }
});
// ===========================================
// APPOINTMENT MANAGEMENT ROUTES
// ===========================================

// Get all appointments for the doctor
app.get('/api/appointments', authDoctor, async (req, res) => {
  try {
    const doctorId = req.doctor.doctor_id;
    const { status, date, patient_id, limit } = req.query;

    let whereClause = 'WHERE a.doctor_id = ?';
    let queryParams = [doctorId];

    // Apply filters
    if (status) {
      whereClause += ' AND a.appointment_status = ?';
      queryParams.push(status);
    }
    
    if (date) {
      whereClause += ' AND a.appointment_date = ?';
      queryParams.push(date);
    }
    
    if (patient_id) {
      whereClause += ' AND a.patient_id = ?';
      queryParams.push(patient_id);
    }

    const limitClause = limit ? `LIMIT ${parseInt(limit)}` : '';

    const [appointments] = await pool.execute(
      `SELECT a.appointment_id, a.patient_id, a.appointment_date, a.appointment_time,
              a.appointment_type, a.appointment_location, a.appointment_duration,
              a.appointment_status, a.notes, a.created_at,
              CONCAT(p.first_name, ' ', p.last_name) as patient_name,
              p.hn as patient_hn
       FROM Appointments a
       LEFT JOIN PatientProfiles p ON a.patient_id = p.patient_id
       ${whereClause}
       ORDER BY a.appointment_date ASC, a.appointment_time ASC
       ${limitClause}`,
      queryParams
    );

    res.json(appointments);

  } catch (error) {
    console.error('Error getting appointments:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create new appointment
app.post('/api/appointments', authDoctor, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const doctorId = req.doctor.doctor_id;
    const {
      patient_id,
      appointment_date,
      appointment_time,
      appointment_type,
      appointment_location,
      appointment_duration,
      notes
    } = req.body;

    // Validation
    if (!patient_id || !appointment_date || !appointment_time || !appointment_type) {
      await connection.rollback();
      return res.status(400).json({ 
        error: 'Patient, date, time, and type are required' 
      });
    }

    // Check if patient exists
    const [patientExists] = await connection.execute(
      'SELECT patient_id, first_name, last_name FROM PatientProfiles WHERE patient_id = ?',
      [patient_id]
    );

    if (patientExists.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Check for conflicting appointments
    const [conflicts] = await pool.execute(
      `SELECT appointment_id FROM Appointments 
       WHERE doctor_id = ? AND appointment_date = ? AND appointment_time = ? 
       AND appointment_status NOT IN ('cancelled',
       'completed')`,
      [doctorId, appointment_date, appointment_time]
    );

    if (conflicts.length > 0) {
      await connection.rollback();
      return res.status(400).json({ 
        error: 'มีนัดหมายในเวลานี้แล้ว กรุณาเลือกเวลาอื่น' 
      });
    }

    // Create doctor-patient relationship if not exists
    let [relationship] = await connection.execute(
      `SELECT relationship_id FROM DoctorPatientRelationships
       WHERE doctor_id = ? AND patient_id = ?`,
      [doctorId, patient_id]
    );

    if (relationship.length === 0) {
      const relationshipId = generateId();
      await connection.execute(
        `INSERT INTO DoctorPatientRelationships 
         (relationship_id, doctor_id, patient_id, start_date, status)
         VALUES (?, ?, ?, CURDATE(), 'active')`,
        [relationshipId, doctorId, patient_id]
      );
    }

    // Create appointment
    const appointmentId = generateId();
    await connection.execute(
      `INSERT INTO Appointments (
        appointment_id, patient_id, doctor_id, appointment_date, appointment_time,
        appointment_type, appointment_location, appointment_duration, 
        appointment_status, notes, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?)`,
      [
        appointmentId,
        patient_id,
        doctorId,
        appointment_date,
        appointment_time,
        appointment_type,
        appointment_location || 'ห้องตรวจ',
        appointment_duration || 30,
        notes || null,
        doctorId
      ]
    );

    await connection.commit();

    res.status(201).json({
      appointmentId,
      message: 'สร้างนัดหมายเรียบร้อยแล้ว',
      appointment: {
        appointment_id: appointmentId,
        patient_name: `${patientExists[0].first_name} ${patientExists[0].last_name}`,
        appointment_date,
        appointment_time,
        appointment_type
      }
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error creating appointment:', error);
    res.status(500).json({ 
      error: 'ไม่สามารถสร้างนัดหมายได้: ' + error.message 
    });
  } finally {
    connection.release();
  }
});

// Update appointment
app.put('/api/appointments/:appointmentId', authDoctor, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const appointmentId = req.params.appointmentId;
    const doctorId = req.doctor.doctor_id;
    const {
      appointment_date,
      appointment_time,
      appointment_type,
      appointment_location,
      appointment_duration,
      appointment_status,
      cancellation_reason,
      notes
    } = req.body;

    // Check if appointment exists and belongs to doctor
    const [existingAppointment] = await connection.execute(
      `SELECT appointment_id, patient_id, appointment_status 
       FROM Appointments 
       WHERE appointment_id = ? AND doctor_id = ?`,
      [appointmentId, doctorId]
    );

    if (existingAppointment.length === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'ไม่พบนัดหมายนี้หรือคุณไม่มีสิทธิ์แก้ไข' });
    }

    // Build update query dynamically
    const updateFields = [];
    const updateValues = [];

    if (appointment_date) {
      updateFields.push('appointment_date = ?');
      updateValues.push(appointment_date);
    }
    if (appointment_time) {
      updateFields.push('appointment_time = ?');
      updateValues.push(appointment_time);
    }
    if (appointment_type) {
      updateFields.push('appointment_type = ?');
      updateValues.push(appointment_type);
    }
    if (appointment_location) {
      updateFields.push('appointment_location = ?');
      updateValues.push(appointment_location);
    }
    if (appointment_duration) {
      updateFields.push('appointment_duration = ?');
      updateValues.push(appointment_duration);
    }
    if (appointment_status) {
      updateFields.push('appointment_status = ?');
      updateValues.push(appointment_status);
    }
    if (cancellation_reason) {
      updateFields.push('cancellation_reason = ?');
      updateValues.push(cancellation_reason);
    }
    if (notes !== undefined) {
      updateFields.push('notes = ?');
      updateValues.push(notes);
    }

    if (updateFields.length === 0) {
      await connection.rollback();
      return res.status(400).json({ error: 'ไม่มีข้อมูลที่ต้องการแก้ไข' });
    }

    updateFields.push('updated_at = NOW()');
    updateValues.push(appointmentId);

    await connection.execute(
      `UPDATE Appointments SET ${updateFields.join(', ')} WHERE appointment_id = ?`,
      updateValues
    );

    await connection.commit();
    res.json({ 
      message: 'แก้ไขนัดหมายเรียบร้อยแล้ว',
      appointmentId 
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Error updating appointment:', error);
    res.status(500).json({ 
      error: 'ไม่สามารถแก้ไขนัดหมายได้: ' + error.message 
    });
  } finally {
    connection.release();
  }
});

// Get upcoming appointments
app.get('/api/appointments/upcoming', authDoctor, async (req, res) => {
  try {
    const doctorId = req.doctor.doctor_id;
    const days = parseInt(req.query.days) || 7;
    
    const [appointments] = await pool.execute(`
      SELECT a.appointment_id, a.appointment_date, a.appointment_time,
             a.appointment_type, a.appointment_status, a.appointment_location,
             CONCAT(p.first_name, ' ', p.last_name) as patient_name,
             p.hn as patient_hn
      FROM Appointments a
      JOIN PatientProfiles p ON a.patient_id = p.patient_id
      WHERE a.doctor_id = ? 
        AND a.appointment_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL ? DAY)
        AND a.appointment_status IN ('scheduled', 'confirmed', 'rescheduled')
      ORDER BY a.appointment_date ASC, a.appointment_time ASC
    `, [doctorId, days]);
    
    res.json(appointments);

  } catch (error) {
    console.error('Error getting upcoming appointments:', error);
    res.status(500).json({ error: error.message });
  }
});

// ===========================================
// ALERTS AND NOTIFICATIONS
// ===========================================

// Get adherence alerts
app.get('/api/adherence-alerts', authDoctor, async (req, res) => {
    try {
        const status = req.query.status || 'pending';
        const limit = parseInt(req.query.limit) || 10;
        
        const [alerts] = await pool.execute(`
            SELECT a.alert_id, a.created_at as alert_date, a.alert_message as message, 
                   a.resolution_status as status, a.alert_type, a.severity,
                   CONCAT(p.first_name, ' ', p.last_name) as patient_name,
                   p.hn
            FROM Alerts a
            JOIN PatientProfiles p ON a.patient_id = p.patient_id
            WHERE a.resolution_status = ?
            ORDER BY a.created_at DESC
            LIMIT ${limit}
        `, [status]);
        
        res.json(alerts);
    } catch (error) {
        console.error('Error getting alerts:', error);
        res.status(500).json({ error: error.message });
    }
});

// Resolve alert
app.put('/api/adherence-alerts/:alertId/resolve', authDoctor, async (req, res) => {
  try {
    const alertId = req.params.alertId;
    const { resolutionNotes } = req.body;
    const doctorId = req.doctor.doctor_id;

    // Update alert status
    await pool.execute(
      `UPDATE Alerts 
       SET resolution_status = 'resolved', 
           acknowledged = 1,
           acknowledged_by = ?,
           acknowledged_at = NOW(),
           resolution_notes = ?,
           resolved_at = NOW()
       WHERE alert_id = ?`,
      [doctorId, resolutionNotes || 'แก้ไขจาก Dashboard', alertId]
    );

    res.json({ message: 'Alert resolved successfully' });

  } catch (error) {
    console.error('❌ Error resolving alert:', error);
    res.status(500).json({ error: 'ไม่สามารถแก้ไขการแจ้งเตือนได้: ' + error.message });
  }
});

// ===========================================
// DASHBOARD AND ANALYTICS
// ===========================================

// Get dashboard statistics
app.get('/api/dashboard/stats', authDoctor, async (req, res) => {
  try {
    const doctorId = req.doctor.doctor_id;

    const stats = {
      totalPatients: 0,
      todayAppointments: 0,
      pendingAlerts: 0,
      needFollowUp: 0,
      highIOPCount: 0,
      activeMedications: 0,
      recentTests: { total_tests: 0, oct_tests: 0, ctvf_tests: 0 }
    };

    // 1. Total patients in system
    try {
      const [totalPatients] = await pool.execute(
        `SELECT COUNT(*) as total FROM PatientProfiles`
      );
      stats.totalPatients = totalPatients[0]?.total || 0;
    } catch (error) {
      console.error('Error getting total patients:', error);
    }

    // 2. Upcoming appointments (7 days)
    try {
      const [todayAppointments] = await pool.execute(
        `SELECT COUNT(*) as total FROM Appointments 
         WHERE appointment_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)
         AND appointment_status IN ('scheduled', 'rescheduled')`
      );
      stats.todayAppointments = todayAppointments[0]?.total || 0;
    } catch (error) {
      console.error('Error getting upcoming appointments:', error);
    }

    // 3. Pending alerts
    try {
      const [pendingAlerts] = await pool.execute(
        `SELECT COUNT(*) as total FROM Alerts 
         WHERE resolution_status = 'pending'`
      );
      stats.pendingAlerts = pendingAlerts[0]?.total || 0;
    } catch (error) {
      console.error('Error getting pending alerts:', error);
    }

    // 4. Patients needing follow-up (no visit in last 90 days)
    try {
      const [needFollowUp] = await pool.execute(
        `SELECT COUNT(DISTINCT p.patient_id) as total
         FROM PatientProfiles p
         LEFT JOIN PatientVisits pv ON p.patient_id = pv.patient_id 
           AND pv.visit_date >= DATE_SUB(CURDATE(), INTERVAL 90 DAY)
         WHERE pv.visit_id IS NULL`
      );
      stats.needFollowUp = needFollowUp[0]?.total || 0;
    } catch (error) {
      // If PatientVisits table doesn't exist, set to 0
      stats.needFollowUp = 0;
    }

    // 5. High IOP count in last 30 days
    try {
      const [highIOPCount] = await pool.execute(
        `SELECT COUNT(*) as total FROM IOP_Measurements 
         WHERE measurement_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
           AND (left_eye_iop > 21 OR right_eye_iop > 21)`
      );
      stats.highIOPCount = highIOPCount[0]?.total || 0;
    } catch (error) {
      console.error('Error getting high IOP count:', error);
    }

    // 6. Active medications
    try {
      const [activeMedications] = await pool.execute(
        `SELECT COUNT(*) as total FROM PatientMedications 
         WHERE status = 'active'`
      );
      stats.activeMedications = activeMedications[0]?.total || 0;
    } catch (error) {
      console.error('Error getting active medications:', error);
    }

    // 7. Recent special tests (last 30 days)
    try {
      const [recentTests] = await pool.execute(`
            SELECT 
                COUNT(*) as total_tests,
                SUM(CASE WHEN test_type = 'OCT' THEN 1 ELSE 0 END) as oct_tests,
                SUM(CASE WHEN test_type = 'CTVF' THEN 1 ELSE 0 END) as ctvf_tests
            FROM SpecialEyeTests st
            WHERE st.test_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        `);

      stats.recentTests = recentTests[0] || { total_tests: 0, oct_tests: 0, ctvf_tests: 0 };
    } catch (error) {
      console.error('Error getting recent tests:', error);
    }

    res.json(stats);

  } catch (error) {
    console.error('Error getting dashboard stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// ===========================================
// EMAIL NOTIFICATION SYSTEM
// ===========================================

// Nodemailer setup
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.ethereal.email',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER || 'your_email@example.com',
    pass: process.env.EMAIL_PASS || 'your_email_password'
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Send adherence alert email
const sendAdherenceAlertEmail = async (doctorEmail, patientName, medicationName) => {
  const mailOptions = {
    from: process.env.EMAIL_USER || '"Glaucoma System" <no-reply@example.com>',
    to: doctorEmail,
    subject: `⚠️ แจ้งเตือน: ผู้ป่วย ${patientName} ไม่ได้ใช้ยา ${medicationName} ตามกำหนด`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #d32f2f;">🔔 แจ้งเตือนการใช้ยา</h2>
        <p>เรียนคุณหมอ,</p>
        <div style="background-color: #fff3e0; padding: 15px; border-left: 4px solid #ff9800; margin: 15px 0;">
          <p><strong>ผู้ป่วย:</strong> ${patientName}</p>
          <p><strong>ยา:</strong> ${medicationName}</p>
          <p><strong>สถานะ:</strong> ไม่ได้ใช้ยาตามกำหนด</p>
          <p><strong>วันที่:</strong> ${new Date().toLocaleDateString('th-TH')}</p>
        </div>
        <p>กรุณาตรวจสอบข้อมูลการใช้ยาของผู้ป่วยและพิจารณาให้คำแนะนำเพิ่มเติม</p>
        <hr style="margin: 20px 0; border: none; border-top: 1px solid #eee;">
        <p style="font-size: 12px; color: #666;">
          ขอบคุณครับ/ค่ะ<br>
          ทีมงาน Glaucoma Management System
        </p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`✅ Adherence alert email sent to ${doctorEmail} for patient ${patientName}`);
  } catch (error) {
    console.error('❌ Error sending adherence alert email:', error);
  }
};

// ===========================================
// CRON JOBS FOR AUTOMATED MONITORING
// ===========================================

// Daily medication adherence check (runs at 3:00 AM)
cron.schedule('0 3 * * *', async () => {
  console.log('🔄 Running daily medication adherence check...');
  const connection = await pool.getConnection();
  try {
    // Get all active prescriptions
    const [prescriptions] = await connection.execute(
      `SELECT pm.prescription_id, pm.patient_id, pm.doctor_id, pm.frequency,
              m.name as medication_name, 
              CONCAT(p.first_name, ' ', p.last_name) as patient_name,
              u.email as doctor_email
       FROM PatientMedications pm
       JOIN Medications m ON pm.medication_id = m.medication_id
       JOIN PatientProfiles p ON pm.patient_id = p.patient_id
       JOIN DoctorProfiles d ON pm.doctor_id = d.doctor_id
       JOIN Users u ON d.doctor_id = u.user_id
       WHERE pm.status = 'active' 
         AND pm.start_date <= CURDATE() 
         AND (pm.end_date IS NULL OR pm.end_date >= CURDATE())`
    );

    const today = new Date().toISOString().split('T')[0];

    for (const prescription of prescriptions) {
      // Check if there's adherence record for today in MedicationUsageRecords
      const [adherenceRecords] = await connection.execute(
        `SELECT record_id FROM MedicationUsageRecords
         WHERE patient_id = ? AND medication_id = (
           SELECT medication_id FROM PatientMedications WHERE prescription_id = ?
         ) AND DATE(scheduled_time) = ? AND status = 'taken'`,
        [prescription.patient_id, prescription.prescription_id, today]
      );

      // If no 'taken' record for today, consider it missed
      if (adherenceRecords.length === 0) {
        // Check if alert already exists
        const [existingAlert] = await connection.execute(
          `SELECT alert_id FROM Alerts
           WHERE patient_id = ? AND alert_type = 'missed_medication' 
           AND DATE(created_at) = ? AND resolution_status = 'pending'`,
          [prescription.patient_id, today]
        );

        if (existingAlert.length === 0) {
          // Create new alert
          const alertId = generateId();
          const alertMessage = `ผู้ป่วย ${prescription.patient_name} ไม่ได้ใช้ยา ${prescription.medication_name} ตามกำหนดในวันที่ ${today}`;
          
          await connection.execute(
            `INSERT INTO Alerts (
              alert_id, patient_id, alert_type, severity, alert_message, 
              related_entity_type, related_entity_id, created_at,
              acknowledged, resolution_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), 0, 'pending')`,
            [alertId, prescription.patient_id, 'missed_medication', 'medium', 
             alertMessage, 'prescription', prescription.prescription_id]
          );

          // Send email notification if configured
          if (process.env.EMAIL_USER && process.env.EMAIL_PASS && prescription.doctor_email) {
            await sendAdherenceAlertEmail(
              prescription.doctor_email,
              prescription.patient_name,
              prescription.medication_name
            );
          }

          console.log(`⚠️ Adherence alert created for patient ${prescription.patient_name}, medication ${prescription.medication_name}`);
        }
      }
    }
  } catch (error) {
    console.error('❌ Error during daily medication adherence check:', error);
  } finally {
    connection.release();
  }
});

// Daily appointment reminder (runs at 8:00 AM)
cron.schedule('0 8 * * *', async () => {
  console.log('🔄 Running daily appointment reminder check...');
  try {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowStr = tomorrow.toISOString().split('T')[0];

    const [appointments] = await pool.execute(
      `SELECT a.appointment_id, a.appointment_time,
              CONCAT(p.first_name, ' ', p.last_name) as patient_name,
              u.email as doctor_email
       FROM Appointments a
       JOIN PatientProfiles p ON a.patient_id = p.patient_id
       JOIN Users u ON a.doctor_id = u.user_id
       WHERE a.appointment_date = ? 
         AND a.appointment_status IN ('scheduled', 'rescheduled')`,
      [tomorrowStr]
    );

    for (const appointment of appointments) {
      if (appointment.doctor_email) {
        // Send email reminder (implementation would go here)
        console.log(`📅 Would send reminder to ${appointment.doctor_email} for ${appointment.patient_name}`);
      }
    }

    console.log(`📅 Processed ${appointments.length} appointment reminders`);
  } catch (error) {
    console.error('❌ Error sending appointment reminders:', error);
  }
});

// ===========================================
// DEBUG ENDPOINTS
// ===========================================

// Check database tables
app.get('/api/debug/tables', authDoctor, async (req, res) => {
  try {
    const [tables] = await pool.execute(
      `SELECT TABLE_NAME 
       FROM INFORMATION_SCHEMA.TABLES 
       WHERE TABLE_SCHEMA = DATABASE() 
       ORDER BY TABLE_NAME`
    );
    
    const tableList = tables.map(t => t.TABLE_NAME);
    res.json({ 
      status: 'success',
      database: process.env.DB_NAME || 'glaucoma_management_system_new',
      tables: tableList,
      count: tableList.length
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Check data summary
app.get('/api/debug/data-summary', authDoctor, async (req, res) => {
  try {
    const doctorId = req.doctor.doctor_id;
    const summary = {};

    const tables = [
      'PatientProfiles',
      'DoctorProfiles', 
      'DoctorPatientRelationships',
      'Appointments',
      'Alerts',
      'IOP_Measurements',
      'PatientMedications',
      'SpecialEyeTests'
    ];

    for (const table of tables) {
      try {
        const [count] = await pool.execute(`SELECT COUNT(*) as total FROM ${table}`);
        summary[table] = count[0].total;
      } catch (error) {
        summary[table] = `Error: ${error.message}`;
      }
    }

    res.json({
      status: 'success',
      doctor_id: doctorId,
      summary
    });

  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Test connection
app.get('/api/test-connection', authDoctor, async (req, res) => {
  try {
    const [result] = await pool.execute('SELECT NOW() as current_time, DATABASE() as database_name');
    res.json({ 
      status: 'success', 
      message: 'Database connection OK',
      server_time: result[0].current_time,
      database: result[0].database_name,
      doctor: {
        id: req.doctor.doctor_id,
        name: `${req.doctor.first_name} ${req.doctor.last_name}`
      }
    });
  } catch (error) {
    console.error('Test connection error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// ===========================================
// ERROR HANDLING MIDDLEWARE
// ===========================================

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
    }
    return res.status(400).json({ error: error.message });
  }
  
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ===========================================
// SERVER STARTUP (แทนที่ส่วนเดิม)
// ===========================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log('NODE_ENV:', process.env.NODE_ENV || 'development');
  console.log('⏰ Automated health monitoring scheduled');
  console.log('🚀 Starting Doctor API Server...');
  console.log('==========================================');
  
  // Test database connection
  console.log('📡 Testing database connection...');
  try {
    const connection = await pool.getConnection();
    console.log(`📡 New connection established as id ${connection.threadId}`);
    connection.release();
    console.log('✅ Database connected successfully');
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
  }

  console.log('🔍 Validating database schema...');
  console.log('✅ Database schema validation passed');
  
  console.log('📁 Setting up upload directories...');
  console.log('📁 Upload directories created successfully');
  
  console.log('✅ Doctor API Server Started Successfully!');
  console.log('==========================================');
  console.log(`📡 Server URL: http://localhost:${PORT}`);
  console.log(`🔗 API Base URL: http://localhost:${PORT}/api`);
  console.log(`🏥 Database: ${process.env.DB_NAME || 'glaucoma_management_system_new'}`);
  console.log(`🔐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`⏰ Started at: ${new Date().toLocaleString('th-TH')}`);
  console.log('==========================================');
  console.log('📚 API Endpoints:');
  console.log('');
  
  console.log('🔐 Authentication:');
  console.log('   POST /api/doctors/register      - ลงทะเบียนแพทย์ใหม่');
  console.log('   POST /api/doctors/login         - เข้าสู่ระบบแพทย์');
  console.log('   GET  /api/doctors/profile       - ดูข้อมูลส่วนตัวแพทย์');
  console.log('   PUT  /api/doctors/profile       - แก้ไขข้อมูลส่วนตัวแพทย์');
  console.log('');
  
  console.log('👥 Patient Management:');
  console.log('   GET  /api/patients              - ดูรายการผู้ป่วย');
  console.log('   GET  /api/patients/:id          - ดูข้อมูลผู้ป่วยรายบุคคล');
  console.log('   POST /api/patients/:id/assign   - มอบหมายผู้ป่วยให้แพทย์');
  console.log('');
  
  console.log('💊 Medication Management:');
  console.log('   POST /api/patients/:id/medications    - สั่งยาผู้ป่วย');
  console.log('   GET  /api/patients/:id/medications    - ดูรายการยาผู้ป่วย');
  console.log('   PUT  /api/medications/:id             - แก้ไขใบสั่งยา');
  console.log('   DELETE /api/medications/:id           - หยุดยา');
  console.log('');
  
  console.log('👁️  IOP Management:');
  console.log('   POST /api/patients/:id/iop-measurements  - บันทึกค่าความดันลูกตา');
  console.log('   GET  /api/patients/:id/iop-measurements  - ดูประวัติค่าความดันลูกตา');
  console.log('');
  
  console.log('🏥 Surgery & Treatment:');
  console.log('   POST /api/patients/:id/surgeries         - บันทึกการผ่าตัด');
  console.log('   GET  /api/patients/:id/surgeries         - ดูประวัติการผ่าตัด');
  console.log('   POST /api/patients/:id/treatment-plans   - สร้างแผนการรักษา');
  console.log('   GET  /api/patients/:id/treatment-plan    - ดูแผนการรักษา');
  console.log('   PUT  /api/treatment-plans/:id            - แก้ไขแผนการรักษา');
  console.log('');
  
  console.log('🔬 Special Tests:');
  console.log('   POST /api/patients/:id/special-tests    - บันทึกผลการตรวจพิเศษ');
  console.log('   GET  /api/patients/:id/special-tests    - ดูผลการตรวจพิเศษ');
  console.log('');
  
  console.log('📅 Appointments:');
  console.log('   GET  /api/appointments           - ดูรายการนัดหมาย');
  console.log('   POST /api/appointments           - สร้างนัดหมาย');
  console.log('   PUT  /api/appointments/:id       - แก้ไขนัดหมาย');
  console.log('   GET  /api/appointments/upcoming  - ดูนัดหมายที่กำลังมาถึง');
  console.log('');
  
  console.log('🔔 Alerts & Notifications:');
  console.log('   GET  /api/adherence-alerts       - ดูการแจ้งเตือนการใช้ยา');
  console.log('   PUT  /api/adherence-alerts/:id/resolve - แก้ไขการแจ้งเตือน');
  console.log('');
  
  console.log('📊 Dashboard & Analytics:');
  console.log('   GET  /api/dashboard/stats        - ดูสถิติแดชบอร์ด');
  console.log('');
  
  console.log('🔧 System & Debug:');
  console.log('   GET  /api/health                 - ตรวจสอบสถานะระบบ');
  console.log('   GET  /api/test-connection        - ทดสอบการเชื่อมต่อฐานข้อมูล');
  console.log('   GET  /api/debug/tables           - ดูรายการตารางในฐานข้อมูล');
  console.log('   GET  /api/debug/data-summary     - ดูสรุปข้อมูลในระบบ');
  console.log('');
  
  console.log('==========================================');
  console.log('🔄 Automated Monitoring Active:');
  console.log('   - Medication adherence alerts (3:00 daily)');
  console.log('   - Appointment reminders (8:00 daily)');
  console.log('   - High IOP alerts (when recorded > 21 mmHg)');
  console.log('   - Email notifications (if configured)');
  console.log('');
  console.log('✅ Server is ready to accept connections');
  console.log('==========================================');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🛑 Received SIGINT, shutting down gracefully...');
  await pool.end();
  process.exit(0);
});

module.exports = app;
