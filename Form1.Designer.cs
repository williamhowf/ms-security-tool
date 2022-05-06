namespace SecurityApplication
{
    partial class SecurityForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(SecurityForm));
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.SaltResult = new System.Windows.Forms.TextBox();
            this.PasswordResult = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.PasswordResultLabel = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.ResetPasswordGenerator = new System.Windows.Forms.Button();
            this.GeneratePassword = new System.Windows.Forms.Button();
            this.panel1 = new System.Windows.Forms.Panel();
            this.SaltRandomButton = new System.Windows.Forms.RadioButton();
            this.SaltPrefixButton = new System.Windows.Forms.RadioButton();
            this.SaltPrefixInput = new System.Windows.Forms.TextBox();
            this.SHA512Button = new System.Windows.Forms.RadioButton();
            this.SHA256Button = new System.Windows.Forms.RadioButton();
            this.SHA1Button = new System.Windows.Forms.RadioButton();
            this.label3 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.plainPassword = new System.Windows.Forms.TextBox();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.groupBox4 = new System.Windows.Forms.GroupBox();
            this.SignatureResult = new System.Windows.Forms.TextBox();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.SG_EN_F2 = new System.Windows.Forms.CheckBox();
            this.SG_EN_F1 = new System.Windows.Forms.CheckBox();
            this.ResetSignatureGenerator = new System.Windows.Forms.Button();
            this.SignInputText3 = new System.Windows.Forms.TextBox();
            this.SignInputText2 = new System.Windows.Forms.TextBox();
            this.SignInputText1 = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.GenerateSignature = new System.Windows.Forms.Button();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.groupBox6 = new System.Windows.Forms.GroupBox();
            this.HashedResultPassword = new System.Windows.Forms.TextBox();
            this.label11 = new System.Windows.Forms.Label();
            this.EncryptedResultPassword = new System.Windows.Forms.TextBox();
            this.label9 = new System.Windows.Forms.Label();
            this.groupBox5 = new System.Windows.Forms.GroupBox();
            this.ResetPasswordEncryptor = new System.Windows.Forms.Button();
            this.EN_SHA512Button = new System.Windows.Forms.RadioButton();
            this.EN_SHA256Button = new System.Windows.Forms.RadioButton();
            this.EN_SHA1Button = new System.Windows.Forms.RadioButton();
            this.label8 = new System.Windows.Forms.Label();
            this.PasswordToEncrypt = new System.Windows.Forms.TextBox();
            this.label10 = new System.Windows.Forms.Label();
            this.PasswordEncryptor = new System.Windows.Forms.Button();
            this.Pass = new System.Windows.Forms.TabPage();
            this.groupBox9 = new System.Windows.Forms.GroupBox();
            this.DecipherPassword = new System.Windows.Forms.TextBox();
            this.label17 = new System.Windows.Forms.Label();
            this.groupBox10 = new System.Windows.Forms.GroupBox();
            this.PasswordDecryptorReset = new System.Windows.Forms.Button();
            this.CipherPassword = new System.Windows.Forms.TextBox();
            this.label19 = new System.Windows.Forms.Label();
            this.PasswordDecrptorGenerate = new System.Windows.Forms.Button();
            this.tabPage4 = new System.Windows.Forms.TabPage();
            this.groupBox11 = new System.Windows.Forms.GroupBox();
            this.SignVerifiedResult = new System.Windows.Forms.TextBox();
            this.groupBox12 = new System.Windows.Forms.GroupBox();
            this.Field2Checked = new System.Windows.Forms.CheckBox();
            this.Field1Checked = new System.Windows.Forms.CheckBox();
            this.VerifyFieldSign = new System.Windows.Forms.TextBox();
            this.label21 = new System.Windows.Forms.Label();
            this.ResetVerify = new System.Windows.Forms.Button();
            this.VerifyField3 = new System.Windows.Forms.TextBox();
            this.VerifyField2 = new System.Windows.Forms.TextBox();
            this.VerifyField1 = new System.Windows.Forms.TextBox();
            this.label16 = new System.Windows.Forms.Label();
            this.label18 = new System.Windows.Forms.Label();
            this.label20 = new System.Windows.Forms.Label();
            this.SignVerify = new System.Windows.Forms.Button();
            this.tabPage5 = new System.Windows.Forms.TabPage();
            this.groupBox14 = new System.Windows.Forms.GroupBox();
            this.FileOutputExportSecretKey = new System.Windows.Forms.TextBox();
            this.label23 = new System.Windows.Forms.Label();
            this.exportSecret = new System.Windows.Forms.Button();
            this.secretkey64box = new System.Windows.Forms.TextBox();
            this.label22 = new System.Windows.Forms.Label();
            this.groupBox13 = new System.Windows.Forms.GroupBox();
            this.SK_SHA512 = new System.Windows.Forms.RadioButton();
            this.SK_SHA256 = new System.Windows.Forms.RadioButton();
            this.label24 = new System.Windows.Forms.Label();
            this.resetSecret = new System.Windows.Forms.Button();
            this.generateSecret = new System.Windows.Forms.Button();
            this.secretmsgbox = new System.Windows.Forms.TextBox();
            this.label25 = new System.Windows.Forms.Label();
            this.tabPage6 = new System.Windows.Forms.TabPage();
            this.groupBox15 = new System.Windows.Forms.GroupBox();
            this.label31 = new System.Windows.Forms.Label();
            this.hmac_gen_signaturehexbinary = new System.Windows.Forms.TextBox();
            this.groupBox16 = new System.Windows.Forms.GroupBox();
            this.hmac_gen_defsk = new System.Windows.Forms.CheckBox();
            this.hmac_gen_sk = new System.Windows.Forms.TextBox();
            this.label30 = new System.Windows.Forms.Label();
            this.hmac_gen_sha512 = new System.Windows.Forms.RadioButton();
            this.hmac_gen_sha256 = new System.Windows.Forms.RadioButton();
            this.label28 = new System.Windows.Forms.Label();
            this.hmac_gen_reset = new System.Windows.Forms.Button();
            this.hmac_gen_generator = new System.Windows.Forms.Button();
            this.hmac_gen_msg = new System.Windows.Forms.TextBox();
            this.label29 = new System.Windows.Forms.Label();
            this.tabPage7 = new System.Windows.Forms.TabPage();
            this.groupBox17 = new System.Windows.Forms.GroupBox();
            this.label27 = new System.Windows.Forms.Label();
            this.hmac_ver_signresult = new System.Windows.Forms.TextBox();
            this.groupBox18 = new System.Windows.Forms.GroupBox();
            this.hmac_ver_signature = new System.Windows.Forms.TextBox();
            this.label34 = new System.Windows.Forms.Label();
            this.hmac_ver_defsk = new System.Windows.Forms.CheckBox();
            this.hmac_ver_sk = new System.Windows.Forms.TextBox();
            this.label26 = new System.Windows.Forms.Label();
            this.hmac_ver_sha512 = new System.Windows.Forms.RadioButton();
            this.hmac_ver_sha256 = new System.Windows.Forms.RadioButton();
            this.label32 = new System.Windows.Forms.Label();
            this.hmac_ver_msg = new System.Windows.Forms.TextBox();
            this.label33 = new System.Windows.Forms.Label();
            this.hmac_ver_reset = new System.Windows.Forms.Button();
            this.hmac_ver_generator = new System.Windows.Forms.Button();
            this.PlainTextEncrypt = new System.Windows.Forms.TabPage();
            this.groupBox19 = new System.Windows.Forms.GroupBox();
            this.plainText_enc_result = new System.Windows.Forms.TextBox();
            this.groupBox20 = new System.Windows.Forms.GroupBox();
            this.plainText_enc_ggit_wallet_library_setting = new System.Windows.Forms.CheckBox();
            this.plainText_enc_allow_fileinput = new System.Windows.Forms.CheckBox();
            this.plainText_enc_msg_input = new System.Windows.Forms.TextBox();
            this.plainText_enc_generator = new System.Windows.Forms.Button();
            this.plainText_enc_upload = new System.Windows.Forms.Button();
            this.plainText_enc_defkey = new System.Windows.Forms.CheckBox();
            this.plainText_enc_sk_input = new System.Windows.Forms.TextBox();
            this.label35 = new System.Windows.Forms.Label();
            this.plainText_enc_reset = new System.Windows.Forms.Button();
            this.label37 = new System.Windows.Forms.Label();
            this.tabPage8 = new System.Windows.Forms.TabPage();
            this.groupBox21 = new System.Windows.Forms.GroupBox();
            this.plainText_dec_result = new System.Windows.Forms.TextBox();
            this.groupBox22 = new System.Windows.Forms.GroupBox();
            this.plainText_dec_ggit_wallet_library_setting = new System.Windows.Forms.CheckBox();
            this.plainText_dec_upload = new System.Windows.Forms.Button();
            this.plainText_dec_allow_fileinput = new System.Windows.Forms.CheckBox();
            this.plainText_dec_msg_input = new System.Windows.Forms.TextBox();
            this.plainText_dec_generator = new System.Windows.Forms.Button();
            this.label39 = new System.Windows.Forms.Label();
            this.plainText_dec_defkey = new System.Windows.Forms.CheckBox();
            this.plainText_dec_sk_input = new System.Windows.Forms.TextBox();
            this.label38 = new System.Windows.Forms.Label();
            this.plainText_dec_reset = new System.Windows.Forms.Button();
            this.tabPage9 = new System.Windows.Forms.TabPage();
            this.rsa_encryptor_result_group = new System.Windows.Forms.GroupBox();
            this.rsa_encryptor_result_output = new System.Windows.Forms.TextBox();
            this.rsa_encryptor_input_group = new System.Windows.Forms.GroupBox();
            this.allowed_Encoded = new System.Windows.Forms.CheckBox();
            this.rsa_encryptor_plain_input = new System.Windows.Forms.TextBox();
            this.rsa_encryptor_reset = new System.Windows.Forms.Button();
            this.rsa_encryptor_plain_label = new System.Windows.Forms.Label();
            this.rsa_encryptor_encrypt = new System.Windows.Forms.Button();
            this.tabPage10 = new System.Windows.Forms.TabPage();
            this.rsa_decryptor_result_group = new System.Windows.Forms.GroupBox();
            this.rsa_decryptor_result_output = new System.Windows.Forms.TextBox();
            this.rsa_decryptor_input_group = new System.Windows.Forms.GroupBox();
            this.rsa_decryptor_enc_input = new System.Windows.Forms.TextBox();
            this.rsa_decryptor_reset = new System.Windows.Forms.Button();
            this.rsa_decryptor_enc_label = new System.Windows.Forms.Label();
            this.rsa_decryptor_decrypt = new System.Windows.Forms.Button();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.groupBox7 = new System.Windows.Forms.GroupBox();
            this.textBox1 = new System.Windows.Forms.TextBox();
            this.label12 = new System.Windows.Forms.Label();
            this.textBox2 = new System.Windows.Forms.TextBox();
            this.label13 = new System.Windows.Forms.Label();
            this.groupBox8 = new System.Windows.Forms.GroupBox();
            this.button1 = new System.Windows.Forms.Button();
            this.radioButton1 = new System.Windows.Forms.RadioButton();
            this.radioButton2 = new System.Windows.Forms.RadioButton();
            this.radioButton3 = new System.Windows.Forms.RadioButton();
            this.label14 = new System.Windows.Forms.Label();
            this.textBox3 = new System.Windows.Forms.TextBox();
            this.label15 = new System.Windows.Forms.Label();
            this.button2 = new System.Windows.Forms.Button();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.rsa_encryptor_dropdown = new System.Windows.Forms.ComboBox();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.panel1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.groupBox4.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.tabPage3.SuspendLayout();
            this.groupBox6.SuspendLayout();
            this.groupBox5.SuspendLayout();
            this.Pass.SuspendLayout();
            this.groupBox9.SuspendLayout();
            this.groupBox10.SuspendLayout();
            this.tabPage4.SuspendLayout();
            this.groupBox11.SuspendLayout();
            this.groupBox12.SuspendLayout();
            this.tabPage5.SuspendLayout();
            this.groupBox14.SuspendLayout();
            this.groupBox13.SuspendLayout();
            this.tabPage6.SuspendLayout();
            this.groupBox15.SuspendLayout();
            this.groupBox16.SuspendLayout();
            this.tabPage7.SuspendLayout();
            this.groupBox17.SuspendLayout();
            this.groupBox18.SuspendLayout();
            this.PlainTextEncrypt.SuspendLayout();
            this.groupBox19.SuspendLayout();
            this.groupBox20.SuspendLayout();
            this.tabPage8.SuspendLayout();
            this.groupBox21.SuspendLayout();
            this.groupBox22.SuspendLayout();
            this.tabPage9.SuspendLayout();
            this.rsa_encryptor_result_group.SuspendLayout();
            this.rsa_encryptor_input_group.SuspendLayout();
            this.tabPage10.SuspendLayout();
            this.rsa_decryptor_result_group.SuspendLayout();
            this.rsa_decryptor_input_group.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            this.groupBox7.SuspendLayout();
            this.groupBox8.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Controls.Add(this.tabPage3);
            this.tabControl1.Controls.Add(this.Pass);
            this.tabControl1.Controls.Add(this.tabPage4);
            this.tabControl1.Controls.Add(this.tabPage5);
            this.tabControl1.Controls.Add(this.tabPage6);
            this.tabControl1.Controls.Add(this.tabPage7);
            this.tabControl1.Controls.Add(this.PlainTextEncrypt);
            this.tabControl1.Controls.Add(this.tabPage8);
            this.tabControl1.Controls.Add(this.tabPage9);
            this.tabControl1.Controls.Add(this.tabPage10);
            this.tabControl1.ItemSize = new System.Drawing.Size(108, 18);
            this.tabControl1.Location = new System.Drawing.Point(0, 64);
            this.tabControl1.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(3157, 1316);
            this.tabControl1.TabIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage1.Controls.Add(this.groupBox2);
            this.tabPage1.Controls.Add(this.groupBox1);
            this.tabPage1.Location = new System.Drawing.Point(10, 28);
            this.tabPage1.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage1.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Password Generator";
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.SaltResult);
            this.groupBox2.Controls.Add(this.PasswordResult);
            this.groupBox2.Controls.Add(this.label4);
            this.groupBox2.Controls.Add(this.PasswordResultLabel);
            this.groupBox2.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox2.Location = new System.Drawing.Point(21, 429);
            this.groupBox2.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox2.Size = new System.Drawing.Size(3093, 367);
            this.groupBox2.TabIndex = 3;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Result";
            // 
            // SaltResult
            // 
            this.SaltResult.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.SaltResult.Cursor = System.Windows.Forms.Cursors.Arrow;
            this.SaltResult.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SaltResult.Location = new System.Drawing.Point(336, 238);
            this.SaltResult.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SaltResult.Multiline = true;
            this.SaltResult.Name = "SaltResult";
            this.SaltResult.ReadOnly = true;
            this.SaltResult.Size = new System.Drawing.Size(643, 62);
            this.SaltResult.TabIndex = 5;
            // 
            // PasswordResult
            // 
            this.PasswordResult.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.PasswordResult.CausesValidation = false;
            this.PasswordResult.Cursor = System.Windows.Forms.Cursors.Default;
            this.PasswordResult.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PasswordResult.HideSelection = false;
            this.PasswordResult.ImeMode = System.Windows.Forms.ImeMode.Off;
            this.PasswordResult.Location = new System.Drawing.Point(336, 67);
            this.PasswordResult.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.PasswordResult.Multiline = true;
            this.PasswordResult.Name = "PasswordResult";
            this.PasswordResult.ReadOnly = true;
            this.PasswordResult.Size = new System.Drawing.Size(1717, 143);
            this.PasswordResult.TabIndex = 4;
            this.PasswordResult.TabStop = false;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(21, 253);
            this.label4.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(89, 46);
            this.label4.TabIndex = 3;
            this.label4.Text = "Salt";
            // 
            // PasswordResultLabel
            // 
            this.PasswordResultLabel.AutoSize = true;
            this.PasswordResultLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PasswordResultLabel.Location = new System.Drawing.Point(21, 81);
            this.PasswordResultLabel.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.PasswordResultLabel.Name = "PasswordResultLabel";
            this.PasswordResultLabel.Size = new System.Drawing.Size(196, 46);
            this.PasswordResultLabel.TabIndex = 0;
            this.PasswordResultLabel.Text = "Password";
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.ResetPasswordGenerator);
            this.groupBox1.Controls.Add(this.GeneratePassword);
            this.groupBox1.Controls.Add(this.panel1);
            this.groupBox1.Controls.Add(this.SHA512Button);
            this.groupBox1.Controls.Add(this.SHA256Button);
            this.groupBox1.Controls.Add(this.SHA1Button);
            this.groupBox1.Controls.Add(this.label3);
            this.groupBox1.Controls.Add(this.label2);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Controls.Add(this.plainPassword);
            this.groupBox1.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox1.Location = new System.Drawing.Point(16, 14);
            this.groupBox1.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox1.Size = new System.Drawing.Size(3099, 401);
            this.groupBox1.TabIndex = 2;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Input";
            // 
            // ResetPasswordGenerator
            // 
            this.ResetPasswordGenerator.BackColor = System.Drawing.SystemColors.ControlDark;
            this.ResetPasswordGenerator.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.ResetPasswordGenerator.Location = new System.Drawing.Point(2667, 48);
            this.ResetPasswordGenerator.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.ResetPasswordGenerator.Name = "ResetPasswordGenerator";
            this.ResetPasswordGenerator.Size = new System.Drawing.Size(400, 79);
            this.ResetPasswordGenerator.TabIndex = 12;
            this.ResetPasswordGenerator.Text = "Reset";
            this.ResetPasswordGenerator.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.ResetPasswordGenerator.UseVisualStyleBackColor = false;
            this.ResetPasswordGenerator.Click += new System.EventHandler(this.ResetPasswordGenerator_Click);
            // 
            // GeneratePassword
            // 
            this.GeneratePassword.BackColor = System.Drawing.SystemColors.ControlDark;
            this.GeneratePassword.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.GeneratePassword.Location = new System.Drawing.Point(2667, 143);
            this.GeneratePassword.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.GeneratePassword.Name = "GeneratePassword";
            this.GeneratePassword.Size = new System.Drawing.Size(400, 79);
            this.GeneratePassword.TabIndex = 11;
            this.GeneratePassword.Text = "Generate";
            this.GeneratePassword.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.GeneratePassword.UseVisualStyleBackColor = false;
            this.GeneratePassword.Click += new System.EventHandler(this.GeneratePassword_Click);
            // 
            // panel1
            // 
            this.panel1.BackColor = System.Drawing.Color.Transparent;
            this.panel1.Controls.Add(this.SaltRandomButton);
            this.panel1.Controls.Add(this.SaltPrefixButton);
            this.panel1.Controls.Add(this.SaltPrefixInput);
            this.panel1.Location = new System.Drawing.Point(341, 176);
            this.panel1.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(1413, 105);
            this.panel1.TabIndex = 10;
            // 
            // SaltRandomButton
            // 
            this.SaltRandomButton.AutoSize = true;
            this.SaltRandomButton.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SaltRandomButton.Location = new System.Drawing.Point(8, 19);
            this.SaltRandomButton.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SaltRandomButton.Name = "SaltRandomButton";
            this.SaltRandomButton.Size = new System.Drawing.Size(281, 50);
            this.SaltRandomButton.TabIndex = 3;
            this.SaltRandomButton.TabStop = true;
            this.SaltRandomButton.Text = "Random salt";
            this.SaltRandomButton.UseVisualStyleBackColor = true;
            this.SaltRandomButton.CheckedChanged += new System.EventHandler(this.radioButton1_CheckedChanged);
            // 
            // SaltPrefixButton
            // 
            this.SaltPrefixButton.AutoSize = true;
            this.SaltPrefixButton.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SaltPrefixButton.Location = new System.Drawing.Point(384, 33);
            this.SaltPrefixButton.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SaltPrefixButton.Name = "SaltPrefixButton";
            this.SaltPrefixButton.Size = new System.Drawing.Size(33, 32);
            this.SaltPrefixButton.TabIndex = 4;
            this.SaltPrefixButton.TabStop = true;
            this.SaltPrefixButton.UseVisualStyleBackColor = true;
            this.SaltPrefixButton.CheckedChanged += new System.EventHandler(this.radioButton2_CheckedChanged);
            // 
            // SaltPrefixInput
            // 
            this.SaltPrefixInput.BackColor = System.Drawing.SystemColors.Control;
            this.SaltPrefixInput.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SaltPrefixInput.Location = new System.Drawing.Point(437, 19);
            this.SaltPrefixInput.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SaltPrefixInput.Name = "SaltPrefixInput";
            this.SaltPrefixInput.Size = new System.Drawing.Size(932, 53);
            this.SaltPrefixInput.TabIndex = 5;
            // 
            // SHA512Button
            // 
            this.SHA512Button.AutoSize = true;
            this.SHA512Button.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SHA512Button.Location = new System.Drawing.Point(877, 129);
            this.SHA512Button.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SHA512Button.Name = "SHA512Button";
            this.SHA512Button.Size = new System.Drawing.Size(206, 50);
            this.SHA512Button.TabIndex = 9;
            this.SHA512Button.TabStop = true;
            this.SHA512Button.Text = "SHA512";
            this.SHA512Button.UseVisualStyleBackColor = true;
            // 
            // SHA256Button
            // 
            this.SHA256Button.AutoSize = true;
            this.SHA256Button.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SHA256Button.Location = new System.Drawing.Point(595, 129);
            this.SHA256Button.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SHA256Button.Name = "SHA256Button";
            this.SHA256Button.Size = new System.Drawing.Size(206, 50);
            this.SHA256Button.TabIndex = 8;
            this.SHA256Button.TabStop = true;
            this.SHA256Button.Text = "SHA256";
            this.SHA256Button.UseVisualStyleBackColor = true;
            // 
            // SHA1Button
            // 
            this.SHA1Button.AutoSize = true;
            this.SHA1Button.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SHA1Button.Location = new System.Drawing.Point(349, 131);
            this.SHA1Button.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SHA1Button.Name = "SHA1Button";
            this.SHA1Button.Size = new System.Drawing.Size(162, 50);
            this.SHA1Button.TabIndex = 7;
            this.SHA1Button.TabStop = true;
            this.SHA1Button.Text = "SHA1";
            this.SHA1Button.UseVisualStyleBackColor = true;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(16, 134);
            this.label3.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(293, 46);
            this.label3.TabIndex = 6;
            this.label3.Text = "Hash Algorithm";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(16, 200);
            this.label2.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(89, 46);
            this.label2.TabIndex = 2;
            this.label2.Text = "Salt";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(16, 72);
            this.label1.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(296, 46);
            this.label1.TabIndex = 0;
            this.label1.Text = "Plain Password";
            // 
            // plainPassword
            // 
            this.plainPassword.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainPassword.Location = new System.Drawing.Point(347, 57);
            this.plainPassword.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainPassword.Name = "plainPassword";
            this.plainPassword.Size = new System.Drawing.Size(1364, 53);
            this.plainPassword.TabIndex = 1;
            // 
            // tabPage2
            // 
            this.tabPage2.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage2.Controls.Add(this.groupBox4);
            this.tabPage2.Controls.Add(this.groupBox3);
            this.tabPage2.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tabPage2.Location = new System.Drawing.Point(10, 28);
            this.tabPage2.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage2.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Signature Generator";
            // 
            // groupBox4
            // 
            this.groupBox4.Controls.Add(this.SignatureResult);
            this.groupBox4.Location = new System.Drawing.Point(21, 539);
            this.groupBox4.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox4.Name = "groupBox4";
            this.groupBox4.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox4.Size = new System.Drawing.Size(3093, 389);
            this.groupBox4.TabIndex = 4;
            this.groupBox4.TabStop = false;
            this.groupBox4.Text = "Signature(Base64)";
            // 
            // SignatureResult
            // 
            this.SignatureResult.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.SignatureResult.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SignatureResult.Location = new System.Drawing.Point(19, 69);
            this.SignatureResult.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SignatureResult.Multiline = true;
            this.SignatureResult.Name = "SignatureResult";
            this.SignatureResult.ReadOnly = true;
            this.SignatureResult.Size = new System.Drawing.Size(2035, 289);
            this.SignatureResult.TabIndex = 0;
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.SG_EN_F2);
            this.groupBox3.Controls.Add(this.SG_EN_F1);
            this.groupBox3.Controls.Add(this.ResetSignatureGenerator);
            this.groupBox3.Controls.Add(this.SignInputText3);
            this.groupBox3.Controls.Add(this.SignInputText2);
            this.groupBox3.Controls.Add(this.SignInputText1);
            this.groupBox3.Controls.Add(this.label7);
            this.groupBox3.Controls.Add(this.label6);
            this.groupBox3.Controls.Add(this.label5);
            this.groupBox3.Controls.Add(this.GenerateSignature);
            this.groupBox3.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox3.Location = new System.Drawing.Point(16, 14);
            this.groupBox3.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox3.Size = new System.Drawing.Size(3099, 510);
            this.groupBox3.TabIndex = 3;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Input";
            // 
            // SG_EN_F2
            // 
            this.SG_EN_F2.AutoSize = true;
            this.SG_EN_F2.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SG_EN_F2.Location = new System.Drawing.Point(1613, 155);
            this.SG_EN_F2.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SG_EN_F2.Name = "SG_EN_F2";
            this.SG_EN_F2.Size = new System.Drawing.Size(238, 50);
            this.SG_EN_F2.TabIndex = 24;
            this.SG_EN_F2.Text = "Encrypted";
            this.SG_EN_F2.UseVisualStyleBackColor = true;
            // 
            // SG_EN_F1
            // 
            this.SG_EN_F1.AutoSize = true;
            this.SG_EN_F1.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SG_EN_F1.Location = new System.Drawing.Point(1613, 72);
            this.SG_EN_F1.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SG_EN_F1.Name = "SG_EN_F1";
            this.SG_EN_F1.Size = new System.Drawing.Size(238, 50);
            this.SG_EN_F1.TabIndex = 23;
            this.SG_EN_F1.Text = "Encrypted";
            this.SG_EN_F1.UseVisualStyleBackColor = true;
            // 
            // ResetSignatureGenerator
            // 
            this.ResetSignatureGenerator.BackColor = System.Drawing.SystemColors.ControlDark;
            this.ResetSignatureGenerator.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.ResetSignatureGenerator.Location = new System.Drawing.Point(2667, 48);
            this.ResetSignatureGenerator.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.ResetSignatureGenerator.Name = "ResetSignatureGenerator";
            this.ResetSignatureGenerator.Size = new System.Drawing.Size(400, 79);
            this.ResetSignatureGenerator.TabIndex = 18;
            this.ResetSignatureGenerator.Text = "Reset";
            this.ResetSignatureGenerator.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.ResetSignatureGenerator.UseVisualStyleBackColor = false;
            this.ResetSignatureGenerator.Click += new System.EventHandler(this.ResetSignatureGenerator_Click);
            // 
            // SignInputText3
            // 
            this.SignInputText3.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SignInputText3.Location = new System.Drawing.Point(248, 234);
            this.SignInputText3.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SignInputText3.Name = "SignInputText3";
            this.SignInputText3.Size = new System.Drawing.Size(1343, 53);
            this.SignInputText3.TabIndex = 17;
            // 
            // SignInputText2
            // 
            this.SignInputText2.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SignInputText2.Location = new System.Drawing.Point(248, 150);
            this.SignInputText2.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SignInputText2.Name = "SignInputText2";
            this.SignInputText2.Size = new System.Drawing.Size(1343, 53);
            this.SignInputText2.TabIndex = 16;
            // 
            // SignInputText1
            // 
            this.SignInputText1.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SignInputText1.Location = new System.Drawing.Point(248, 67);
            this.SignInputText1.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SignInputText1.Name = "SignInputText1";
            this.SignInputText1.Size = new System.Drawing.Size(1343, 53);
            this.SignInputText1.TabIndex = 15;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label7.Location = new System.Drawing.Point(0, 241);
            this.label7.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(224, 46);
            this.label7.TabIndex = 14;
            this.label7.Text = "DeviceUuid";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label6.Location = new System.Drawing.Point(8, 165);
            this.label6.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(139, 46);
            this.label6.TabIndex = 13;
            this.label6.Text = "Field 2";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label5.Location = new System.Drawing.Point(8, 81);
            this.label5.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(139, 46);
            this.label5.TabIndex = 12;
            this.label5.Text = "Field 1";
            // 
            // GenerateSignature
            // 
            this.GenerateSignature.BackColor = System.Drawing.SystemColors.ControlDark;
            this.GenerateSignature.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.GenerateSignature.Location = new System.Drawing.Point(2667, 143);
            this.GenerateSignature.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.GenerateSignature.Name = "GenerateSignature";
            this.GenerateSignature.Size = new System.Drawing.Size(400, 79);
            this.GenerateSignature.TabIndex = 11;
            this.GenerateSignature.Text = "Generate";
            this.GenerateSignature.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.GenerateSignature.UseVisualStyleBackColor = false;
            this.GenerateSignature.Click += new System.EventHandler(this.GenerateSignature_Click);
            // 
            // tabPage3
            // 
            this.tabPage3.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage3.Controls.Add(this.groupBox6);
            this.tabPage3.Controls.Add(this.groupBox5);
            this.tabPage3.Location = new System.Drawing.Point(10, 28);
            this.tabPage3.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage3.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage3.TabIndex = 2;
            this.tabPage3.Text = "Password Encryptor";
            // 
            // groupBox6
            // 
            this.groupBox6.Controls.Add(this.HashedResultPassword);
            this.groupBox6.Controls.Add(this.label11);
            this.groupBox6.Controls.Add(this.EncryptedResultPassword);
            this.groupBox6.Controls.Add(this.label9);
            this.groupBox6.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox6.Location = new System.Drawing.Point(19, 417);
            this.groupBox6.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox6.Name = "groupBox6";
            this.groupBox6.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox6.Size = new System.Drawing.Size(3096, 510);
            this.groupBox6.TabIndex = 5;
            this.groupBox6.TabStop = false;
            this.groupBox6.Text = "Result";
            // 
            // HashedResultPassword
            // 
            this.HashedResultPassword.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.HashedResultPassword.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.HashedResultPassword.Location = new System.Drawing.Point(32, 157);
            this.HashedResultPassword.Margin = new System.Windows.Forms.Padding(0);
            this.HashedResultPassword.Multiline = true;
            this.HashedResultPassword.Name = "HashedResultPassword";
            this.HashedResultPassword.ReadOnly = true;
            this.HashedResultPassword.Size = new System.Drawing.Size(2024, 155);
            this.HashedResultPassword.TabIndex = 3;
            this.HashedResultPassword.TabStop = false;
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Location = new System.Drawing.Point(19, 88);
            this.label11.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(454, 61);
            this.label11.TabIndex = 2;
            this.label11.Text = "Hashed Password";
            // 
            // EncryptedResultPassword
            // 
            this.EncryptedResultPassword.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.EncryptedResultPassword.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.EncryptedResultPassword.Location = new System.Drawing.Point(32, 382);
            this.EncryptedResultPassword.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.EncryptedResultPassword.Multiline = true;
            this.EncryptedResultPassword.Name = "EncryptedResultPassword";
            this.EncryptedResultPassword.ReadOnly = true;
            this.EncryptedResultPassword.Size = new System.Drawing.Size(2024, 55);
            this.EncryptedResultPassword.TabIndex = 1;
            this.EncryptedResultPassword.TabStop = false;
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(19, 312);
            this.label9.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(511, 61);
            this.label9.TabIndex = 0;
            this.label9.Text = "Encrypted Password";
            // 
            // groupBox5
            // 
            this.groupBox5.Controls.Add(this.ResetPasswordEncryptor);
            this.groupBox5.Controls.Add(this.EN_SHA512Button);
            this.groupBox5.Controls.Add(this.EN_SHA256Button);
            this.groupBox5.Controls.Add(this.EN_SHA1Button);
            this.groupBox5.Controls.Add(this.label8);
            this.groupBox5.Controls.Add(this.PasswordToEncrypt);
            this.groupBox5.Controls.Add(this.label10);
            this.groupBox5.Controls.Add(this.PasswordEncryptor);
            this.groupBox5.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox5.Location = new System.Drawing.Point(16, 14);
            this.groupBox5.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox5.Name = "groupBox5";
            this.groupBox5.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox5.Size = new System.Drawing.Size(3099, 386);
            this.groupBox5.TabIndex = 4;
            this.groupBox5.TabStop = false;
            this.groupBox5.Text = "Input";
            // 
            // ResetPasswordEncryptor
            // 
            this.ResetPasswordEncryptor.BackColor = System.Drawing.SystemColors.ControlDark;
            this.ResetPasswordEncryptor.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.ResetPasswordEncryptor.Location = new System.Drawing.Point(2667, 48);
            this.ResetPasswordEncryptor.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.ResetPasswordEncryptor.Name = "ResetPasswordEncryptor";
            this.ResetPasswordEncryptor.Size = new System.Drawing.Size(400, 79);
            this.ResetPasswordEncryptor.TabIndex = 20;
            this.ResetPasswordEncryptor.Text = "Reset";
            this.ResetPasswordEncryptor.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.ResetPasswordEncryptor.UseVisualStyleBackColor = false;
            this.ResetPasswordEncryptor.Click += new System.EventHandler(this.ResetPasswordEncryptor_Click);
            // 
            // EN_SHA512Button
            // 
            this.EN_SHA512Button.AutoSize = true;
            this.EN_SHA512Button.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.EN_SHA512Button.Location = new System.Drawing.Point(877, 162);
            this.EN_SHA512Button.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.EN_SHA512Button.Name = "EN_SHA512Button";
            this.EN_SHA512Button.Size = new System.Drawing.Size(206, 50);
            this.EN_SHA512Button.TabIndex = 19;
            this.EN_SHA512Button.TabStop = true;
            this.EN_SHA512Button.Text = "SHA512";
            this.EN_SHA512Button.UseVisualStyleBackColor = true;
            // 
            // EN_SHA256Button
            // 
            this.EN_SHA256Button.AutoSize = true;
            this.EN_SHA256Button.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.EN_SHA256Button.Location = new System.Drawing.Point(595, 162);
            this.EN_SHA256Button.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.EN_SHA256Button.Name = "EN_SHA256Button";
            this.EN_SHA256Button.Size = new System.Drawing.Size(206, 50);
            this.EN_SHA256Button.TabIndex = 18;
            this.EN_SHA256Button.TabStop = true;
            this.EN_SHA256Button.Text = "SHA256";
            this.EN_SHA256Button.UseVisualStyleBackColor = true;
            // 
            // EN_SHA1Button
            // 
            this.EN_SHA1Button.AutoSize = true;
            this.EN_SHA1Button.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.EN_SHA1Button.Location = new System.Drawing.Point(349, 165);
            this.EN_SHA1Button.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.EN_SHA1Button.Name = "EN_SHA1Button";
            this.EN_SHA1Button.Size = new System.Drawing.Size(162, 50);
            this.EN_SHA1Button.TabIndex = 17;
            this.EN_SHA1Button.TabStop = true;
            this.EN_SHA1Button.Text = "SHA1";
            this.EN_SHA1Button.UseVisualStyleBackColor = true;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label8.Location = new System.Drawing.Point(8, 167);
            this.label8.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(293, 46);
            this.label8.TabIndex = 16;
            this.label8.Text = "Hash Algorithm";
            // 
            // PasswordToEncrypt
            // 
            this.PasswordToEncrypt.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.PasswordToEncrypt.Location = new System.Drawing.Point(349, 67);
            this.PasswordToEncrypt.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.PasswordToEncrypt.Name = "PasswordToEncrypt";
            this.PasswordToEncrypt.Size = new System.Drawing.Size(956, 53);
            this.PasswordToEncrypt.TabIndex = 15;
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label10.Location = new System.Drawing.Point(8, 81);
            this.label10.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(296, 46);
            this.label10.TabIndex = 12;
            this.label10.Text = "Plain Password";
            // 
            // PasswordEncryptor
            // 
            this.PasswordEncryptor.BackColor = System.Drawing.SystemColors.ControlDark;
            this.PasswordEncryptor.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.PasswordEncryptor.Location = new System.Drawing.Point(2667, 143);
            this.PasswordEncryptor.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.PasswordEncryptor.Name = "PasswordEncryptor";
            this.PasswordEncryptor.Size = new System.Drawing.Size(400, 79);
            this.PasswordEncryptor.TabIndex = 11;
            this.PasswordEncryptor.Text = "Encrypt";
            this.PasswordEncryptor.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.PasswordEncryptor.UseVisualStyleBackColor = false;
            this.PasswordEncryptor.Click += new System.EventHandler(this.PasswordEncryptor_Click);
            // 
            // Pass
            // 
            this.Pass.BackColor = System.Drawing.SystemColors.ControlLight;
            this.Pass.Controls.Add(this.groupBox9);
            this.Pass.Controls.Add(this.groupBox10);
            this.Pass.Location = new System.Drawing.Point(10, 28);
            this.Pass.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.Pass.Name = "Pass";
            this.Pass.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.Pass.Size = new System.Drawing.Size(3137, 1278);
            this.Pass.TabIndex = 3;
            this.Pass.Text = "Password Decryptor";
            // 
            // groupBox9
            // 
            this.groupBox9.Controls.Add(this.DecipherPassword);
            this.groupBox9.Controls.Add(this.label17);
            this.groupBox9.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox9.Location = new System.Drawing.Point(8, 520);
            this.groupBox9.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox9.Name = "groupBox9";
            this.groupBox9.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox9.Size = new System.Drawing.Size(3107, 384);
            this.groupBox9.TabIndex = 7;
            this.groupBox9.TabStop = false;
            this.groupBox9.Text = "Result";
            // 
            // DecipherPassword
            // 
            this.DecipherPassword.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.DecipherPassword.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.DecipherPassword.Location = new System.Drawing.Point(32, 169);
            this.DecipherPassword.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.DecipherPassword.Multiline = true;
            this.DecipherPassword.Name = "DecipherPassword";
            this.DecipherPassword.ReadOnly = true;
            this.DecipherPassword.Size = new System.Drawing.Size(2037, 129);
            this.DecipherPassword.TabIndex = 1;
            this.DecipherPassword.TabStop = false;
            // 
            // label17
            // 
            this.label17.AutoSize = true;
            this.label17.Location = new System.Drawing.Point(19, 100);
            this.label17.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label17.Name = "label17";
            this.label17.Size = new System.Drawing.Size(514, 61);
            this.label17.TabIndex = 0;
            this.label17.Text = "Decrypted Password";
            // 
            // groupBox10
            // 
            this.groupBox10.Controls.Add(this.PasswordDecryptorReset);
            this.groupBox10.Controls.Add(this.CipherPassword);
            this.groupBox10.Controls.Add(this.label19);
            this.groupBox10.Controls.Add(this.PasswordDecrptorGenerate);
            this.groupBox10.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox10.Location = new System.Drawing.Point(16, 14);
            this.groupBox10.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox10.Name = "groupBox10";
            this.groupBox10.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox10.Size = new System.Drawing.Size(3099, 455);
            this.groupBox10.TabIndex = 6;
            this.groupBox10.TabStop = false;
            this.groupBox10.Text = "Input";
            // 
            // PasswordDecryptorReset
            // 
            this.PasswordDecryptorReset.BackColor = System.Drawing.SystemColors.ControlDark;
            this.PasswordDecryptorReset.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.PasswordDecryptorReset.Location = new System.Drawing.Point(2667, 48);
            this.PasswordDecryptorReset.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.PasswordDecryptorReset.Name = "PasswordDecryptorReset";
            this.PasswordDecryptorReset.Size = new System.Drawing.Size(400, 79);
            this.PasswordDecryptorReset.TabIndex = 20;
            this.PasswordDecryptorReset.Text = "Reset";
            this.PasswordDecryptorReset.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.PasswordDecryptorReset.UseVisualStyleBackColor = false;
            this.PasswordDecryptorReset.Click += new System.EventHandler(this.PasswordDecryptorReset_Click);
            // 
            // CipherPassword
            // 
            this.CipherPassword.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.CipherPassword.Location = new System.Drawing.Point(435, 67);
            this.CipherPassword.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.CipherPassword.Multiline = true;
            this.CipherPassword.Name = "CipherPassword";
            this.CipherPassword.Size = new System.Drawing.Size(1689, 321);
            this.CipherPassword.TabIndex = 15;
            // 
            // label19
            // 
            this.label19.AutoSize = true;
            this.label19.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label19.Location = new System.Drawing.Point(8, 81);
            this.label19.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label19.Name = "label19";
            this.label19.Size = new System.Drawing.Size(387, 46);
            this.label19.TabIndex = 12;
            this.label19.Text = "Encrypted Password";
            // 
            // PasswordDecrptorGenerate
            // 
            this.PasswordDecrptorGenerate.BackColor = System.Drawing.SystemColors.ControlDark;
            this.PasswordDecrptorGenerate.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.PasswordDecrptorGenerate.Location = new System.Drawing.Point(2667, 143);
            this.PasswordDecrptorGenerate.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.PasswordDecrptorGenerate.Name = "PasswordDecrptorGenerate";
            this.PasswordDecrptorGenerate.Size = new System.Drawing.Size(400, 79);
            this.PasswordDecrptorGenerate.TabIndex = 11;
            this.PasswordDecrptorGenerate.Text = "Decrypt";
            this.PasswordDecrptorGenerate.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.PasswordDecrptorGenerate.UseVisualStyleBackColor = false;
            this.PasswordDecrptorGenerate.Click += new System.EventHandler(this.PasswordDecrptorGenerate_Click);
            // 
            // tabPage4
            // 
            this.tabPage4.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage4.Controls.Add(this.groupBox11);
            this.tabPage4.Controls.Add(this.groupBox12);
            this.tabPage4.Location = new System.Drawing.Point(10, 28);
            this.tabPage4.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage4.Name = "tabPage4";
            this.tabPage4.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage4.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage4.TabIndex = 4;
            this.tabPage4.Text = "Signature Verification";
            // 
            // groupBox11
            // 
            this.groupBox11.Controls.Add(this.SignVerifiedResult);
            this.groupBox11.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox11.Location = new System.Drawing.Point(21, 732);
            this.groupBox11.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox11.Name = "groupBox11";
            this.groupBox11.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox11.Size = new System.Drawing.Size(3093, 196);
            this.groupBox11.TabIndex = 6;
            this.groupBox11.TabStop = false;
            this.groupBox11.Text = "Signature Verified";
            // 
            // SignVerifiedResult
            // 
            this.SignVerifiedResult.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.SignVerifiedResult.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SignVerifiedResult.Location = new System.Drawing.Point(19, 69);
            this.SignVerifiedResult.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SignVerifiedResult.Name = "SignVerifiedResult";
            this.SignVerifiedResult.ReadOnly = true;
            this.SignVerifiedResult.Size = new System.Drawing.Size(339, 60);
            this.SignVerifiedResult.TabIndex = 0;
            // 
            // groupBox12
            // 
            this.groupBox12.Controls.Add(this.Field2Checked);
            this.groupBox12.Controls.Add(this.Field1Checked);
            this.groupBox12.Controls.Add(this.VerifyFieldSign);
            this.groupBox12.Controls.Add(this.label21);
            this.groupBox12.Controls.Add(this.ResetVerify);
            this.groupBox12.Controls.Add(this.VerifyField3);
            this.groupBox12.Controls.Add(this.VerifyField2);
            this.groupBox12.Controls.Add(this.VerifyField1);
            this.groupBox12.Controls.Add(this.label16);
            this.groupBox12.Controls.Add(this.label18);
            this.groupBox12.Controls.Add(this.label20);
            this.groupBox12.Controls.Add(this.SignVerify);
            this.groupBox12.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox12.Location = new System.Drawing.Point(16, 14);
            this.groupBox12.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox12.Name = "groupBox12";
            this.groupBox12.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox12.Size = new System.Drawing.Size(3099, 703);
            this.groupBox12.TabIndex = 5;
            this.groupBox12.TabStop = false;
            this.groupBox12.Text = "Input";
            // 
            // Field2Checked
            // 
            this.Field2Checked.AutoSize = true;
            this.Field2Checked.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Field2Checked.Location = new System.Drawing.Point(2147, 150);
            this.Field2Checked.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.Field2Checked.Name = "Field2Checked";
            this.Field2Checked.Size = new System.Drawing.Size(238, 50);
            this.Field2Checked.TabIndex = 22;
            this.Field2Checked.Text = "Encrypted";
            this.Field2Checked.UseVisualStyleBackColor = true;
            // 
            // Field1Checked
            // 
            this.Field1Checked.AutoSize = true;
            this.Field1Checked.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Field1Checked.Location = new System.Drawing.Point(2147, 67);
            this.Field1Checked.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.Field1Checked.Name = "Field1Checked";
            this.Field1Checked.Size = new System.Drawing.Size(238, 50);
            this.Field1Checked.TabIndex = 21;
            this.Field1Checked.Text = "Encrypted";
            this.Field1Checked.UseVisualStyleBackColor = true;
            // 
            // VerifyFieldSign
            // 
            this.VerifyFieldSign.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.VerifyFieldSign.Location = new System.Drawing.Point(248, 310);
            this.VerifyFieldSign.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.VerifyFieldSign.Multiline = true;
            this.VerifyFieldSign.Name = "VerifyFieldSign";
            this.VerifyFieldSign.Size = new System.Drawing.Size(1876, 302);
            this.VerifyFieldSign.TabIndex = 20;
            // 
            // label21
            // 
            this.label21.AutoSize = true;
            this.label21.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label21.Location = new System.Drawing.Point(8, 324);
            this.label21.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label21.Name = "label21";
            this.label21.Size = new System.Drawing.Size(190, 46);
            this.label21.TabIndex = 19;
            this.label21.Text = "Signature";
            // 
            // ResetVerify
            // 
            this.ResetVerify.BackColor = System.Drawing.SystemColors.ControlDark;
            this.ResetVerify.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.ResetVerify.Location = new System.Drawing.Point(2667, 48);
            this.ResetVerify.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.ResetVerify.Name = "ResetVerify";
            this.ResetVerify.Size = new System.Drawing.Size(400, 79);
            this.ResetVerify.TabIndex = 18;
            this.ResetVerify.Text = "Reset";
            this.ResetVerify.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.ResetVerify.UseVisualStyleBackColor = false;
            this.ResetVerify.Click += new System.EventHandler(this.ResetVerify_Click);
            // 
            // VerifyField3
            // 
            this.VerifyField3.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.VerifyField3.Location = new System.Drawing.Point(248, 234);
            this.VerifyField3.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.VerifyField3.Name = "VerifyField3";
            this.VerifyField3.Size = new System.Drawing.Size(1876, 53);
            this.VerifyField3.TabIndex = 17;
            // 
            // VerifyField2
            // 
            this.VerifyField2.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.VerifyField2.Location = new System.Drawing.Point(248, 150);
            this.VerifyField2.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.VerifyField2.Name = "VerifyField2";
            this.VerifyField2.Size = new System.Drawing.Size(1876, 53);
            this.VerifyField2.TabIndex = 16;
            // 
            // VerifyField1
            // 
            this.VerifyField1.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.VerifyField1.Location = new System.Drawing.Point(248, 67);
            this.VerifyField1.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.VerifyField1.Name = "VerifyField1";
            this.VerifyField1.Size = new System.Drawing.Size(1876, 53);
            this.VerifyField1.TabIndex = 15;
            // 
            // label16
            // 
            this.label16.AutoSize = true;
            this.label16.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label16.Location = new System.Drawing.Point(0, 241);
            this.label16.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label16.Name = "label16";
            this.label16.Size = new System.Drawing.Size(224, 46);
            this.label16.TabIndex = 14;
            this.label16.Text = "DeviceUuid";
            // 
            // label18
            // 
            this.label18.AutoSize = true;
            this.label18.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label18.Location = new System.Drawing.Point(8, 165);
            this.label18.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label18.Name = "label18";
            this.label18.Size = new System.Drawing.Size(139, 46);
            this.label18.TabIndex = 13;
            this.label18.Text = "Field 2";
            // 
            // label20
            // 
            this.label20.AutoSize = true;
            this.label20.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label20.Location = new System.Drawing.Point(8, 81);
            this.label20.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label20.Name = "label20";
            this.label20.Size = new System.Drawing.Size(139, 46);
            this.label20.TabIndex = 12;
            this.label20.Text = "Field 1";
            // 
            // SignVerify
            // 
            this.SignVerify.BackColor = System.Drawing.SystemColors.ControlDark;
            this.SignVerify.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.SignVerify.Location = new System.Drawing.Point(2667, 143);
            this.SignVerify.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SignVerify.Name = "SignVerify";
            this.SignVerify.Size = new System.Drawing.Size(400, 79);
            this.SignVerify.TabIndex = 11;
            this.SignVerify.Text = "Verify";
            this.SignVerify.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.SignVerify.UseVisualStyleBackColor = false;
            this.SignVerify.Click += new System.EventHandler(this.SignVerify_Click);
            // 
            // tabPage5
            // 
            this.tabPage5.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage5.Controls.Add(this.groupBox14);
            this.tabPage5.Controls.Add(this.groupBox13);
            this.tabPage5.Location = new System.Drawing.Point(10, 28);
            this.tabPage5.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage5.Name = "tabPage5";
            this.tabPage5.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage5.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage5.TabIndex = 5;
            this.tabPage5.Text = "Secret Key";
            // 
            // groupBox14
            // 
            this.groupBox14.Controls.Add(this.FileOutputExportSecretKey);
            this.groupBox14.Controls.Add(this.label23);
            this.groupBox14.Controls.Add(this.exportSecret);
            this.groupBox14.Controls.Add(this.secretkey64box);
            this.groupBox14.Controls.Add(this.label22);
            this.groupBox14.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox14.Location = new System.Drawing.Point(16, 467);
            this.groupBox14.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox14.Name = "groupBox14";
            this.groupBox14.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox14.Size = new System.Drawing.Size(3099, 460);
            this.groupBox14.TabIndex = 9;
            this.groupBox14.TabStop = false;
            this.groupBox14.Text = "Result";
            // 
            // FileOutputExportSecretKey
            // 
            this.FileOutputExportSecretKey.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.FileOutputExportSecretKey.Location = new System.Drawing.Point(363, 336);
            this.FileOutputExportSecretKey.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.FileOutputExportSecretKey.Name = "FileOutputExportSecretKey";
            this.FileOutputExportSecretKey.Size = new System.Drawing.Size(2281, 53);
            this.FileOutputExportSecretKey.TabIndex = 26;
            // 
            // label23
            // 
            this.label23.AutoSize = true;
            this.label23.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label23.Location = new System.Drawing.Point(21, 343);
            this.label23.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label23.Name = "label23";
            this.label23.Size = new System.Drawing.Size(214, 46);
            this.label23.TabIndex = 25;
            this.label23.Text = "Output File";
            // 
            // exportSecret
            // 
            this.exportSecret.BackColor = System.Drawing.SystemColors.ControlDark;
            this.exportSecret.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.exportSecret.Location = new System.Drawing.Point(2667, 327);
            this.exportSecret.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.exportSecret.Name = "exportSecret";
            this.exportSecret.Size = new System.Drawing.Size(400, 79);
            this.exportSecret.TabIndex = 24;
            this.exportSecret.Text = "Export";
            this.exportSecret.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.exportSecret.UseVisualStyleBackColor = false;
            this.exportSecret.Click += new System.EventHandler(this.exportSecret_Click);
            // 
            // secretkey64box
            // 
            this.secretkey64box.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.secretkey64box.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.secretkey64box.Location = new System.Drawing.Point(32, 169);
            this.secretkey64box.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.secretkey64box.Multiline = true;
            this.secretkey64box.Name = "secretkey64box";
            this.secretkey64box.ReadOnly = true;
            this.secretkey64box.Size = new System.Drawing.Size(2619, 129);
            this.secretkey64box.TabIndex = 1;
            this.secretkey64box.TabStop = false;
            // 
            // label22
            // 
            this.label22.AutoSize = true;
            this.label22.Location = new System.Drawing.Point(19, 100);
            this.label22.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label22.Name = "label22";
            this.label22.Size = new System.Drawing.Size(499, 61);
            this.label22.TabIndex = 0;
            this.label22.Text = "Secret Key(Base64)";
            // 
            // groupBox13
            // 
            this.groupBox13.Controls.Add(this.SK_SHA512);
            this.groupBox13.Controls.Add(this.SK_SHA256);
            this.groupBox13.Controls.Add(this.label24);
            this.groupBox13.Controls.Add(this.resetSecret);
            this.groupBox13.Controls.Add(this.generateSecret);
            this.groupBox13.Controls.Add(this.secretmsgbox);
            this.groupBox13.Controls.Add(this.label25);
            this.groupBox13.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox13.Location = new System.Drawing.Point(16, 14);
            this.groupBox13.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox13.Name = "groupBox13";
            this.groupBox13.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox13.Size = new System.Drawing.Size(3099, 439);
            this.groupBox13.TabIndex = 6;
            this.groupBox13.TabStop = false;
            this.groupBox13.Text = "Input";
            // 
            // SK_SHA512
            // 
            this.SK_SHA512.AutoSize = true;
            this.SK_SHA512.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SK_SHA512.Location = new System.Drawing.Point(640, 160);
            this.SK_SHA512.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SK_SHA512.Name = "SK_SHA512";
            this.SK_SHA512.Size = new System.Drawing.Size(206, 50);
            this.SK_SHA512.TabIndex = 25;
            this.SK_SHA512.Text = "SHA512";
            this.SK_SHA512.UseVisualStyleBackColor = true;
            // 
            // SK_SHA256
            // 
            this.SK_SHA256.AutoSize = true;
            this.SK_SHA256.Checked = true;
            this.SK_SHA256.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.SK_SHA256.Location = new System.Drawing.Point(357, 160);
            this.SK_SHA256.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.SK_SHA256.Name = "SK_SHA256";
            this.SK_SHA256.Size = new System.Drawing.Size(206, 50);
            this.SK_SHA256.TabIndex = 24;
            this.SK_SHA256.TabStop = true;
            this.SK_SHA256.Text = "SHA256";
            this.SK_SHA256.UseVisualStyleBackColor = true;
            // 
            // label24
            // 
            this.label24.AutoSize = true;
            this.label24.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label24.Location = new System.Drawing.Point(16, 160);
            this.label24.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label24.Name = "label24";
            this.label24.Size = new System.Drawing.Size(293, 46);
            this.label24.TabIndex = 22;
            this.label24.Text = "Hash Algorithm";
            // 
            // resetSecret
            // 
            this.resetSecret.BackColor = System.Drawing.SystemColors.ControlDark;
            this.resetSecret.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.resetSecret.Location = new System.Drawing.Point(2667, 48);
            this.resetSecret.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.resetSecret.Name = "resetSecret";
            this.resetSecret.Size = new System.Drawing.Size(400, 79);
            this.resetSecret.TabIndex = 21;
            this.resetSecret.Text = "Reset";
            this.resetSecret.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.resetSecret.UseVisualStyleBackColor = false;
            this.resetSecret.Click += new System.EventHandler(this.resetSecret_Click);
            // 
            // generateSecret
            // 
            this.generateSecret.BackColor = System.Drawing.SystemColors.ControlDark;
            this.generateSecret.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.generateSecret.Location = new System.Drawing.Point(2667, 143);
            this.generateSecret.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.generateSecret.Name = "generateSecret";
            this.generateSecret.Size = new System.Drawing.Size(400, 79);
            this.generateSecret.TabIndex = 18;
            this.generateSecret.Text = "Generate";
            this.generateSecret.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.generateSecret.UseVisualStyleBackColor = false;
            this.generateSecret.Click += new System.EventHandler(this.generateSecret_Click);
            // 
            // secretmsgbox
            // 
            this.secretmsgbox.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.secretmsgbox.Location = new System.Drawing.Point(357, 67);
            this.secretmsgbox.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.secretmsgbox.Name = "secretmsgbox";
            this.secretmsgbox.Size = new System.Drawing.Size(1767, 53);
            this.secretmsgbox.TabIndex = 15;
            // 
            // label25
            // 
            this.label25.AutoSize = true;
            this.label25.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label25.Location = new System.Drawing.Point(8, 74);
            this.label25.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label25.Name = "label25";
            this.label25.Size = new System.Drawing.Size(308, 46);
            this.label25.TabIndex = 12;
            this.label25.Text = "Secret Message";
            // 
            // tabPage6
            // 
            this.tabPage6.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage6.Controls.Add(this.groupBox15);
            this.tabPage6.Controls.Add(this.groupBox16);
            this.tabPage6.Location = new System.Drawing.Point(10, 28);
            this.tabPage6.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage6.Name = "tabPage6";
            this.tabPage6.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage6.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage6.TabIndex = 6;
            this.tabPage6.Text = "HMAC Generator";
            // 
            // groupBox15
            // 
            this.groupBox15.BackColor = System.Drawing.SystemColors.ControlLight;
            this.groupBox15.Controls.Add(this.label31);
            this.groupBox15.Controls.Add(this.hmac_gen_signaturehexbinary);
            this.groupBox15.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox15.Location = new System.Drawing.Point(16, 618);
            this.groupBox15.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox15.Name = "groupBox15";
            this.groupBox15.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox15.Size = new System.Drawing.Size(3099, 331);
            this.groupBox15.TabIndex = 11;
            this.groupBox15.TabStop = false;
            this.groupBox15.Text = "Signature";
            // 
            // label31
            // 
            this.label31.AutoSize = true;
            this.label31.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label31.Location = new System.Drawing.Point(13, 72);
            this.label31.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label31.Name = "label31";
            this.label31.Size = new System.Drawing.Size(205, 46);
            this.label31.TabIndex = 29;
            this.label31.Text = "HexBinary";
            // 
            // hmac_gen_signaturehexbinary
            // 
            this.hmac_gen_signaturehexbinary.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.hmac_gen_signaturehexbinary.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_gen_signaturehexbinary.Location = new System.Drawing.Point(251, 72);
            this.hmac_gen_signaturehexbinary.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_gen_signaturehexbinary.Multiline = true;
            this.hmac_gen_signaturehexbinary.Name = "hmac_gen_signaturehexbinary";
            this.hmac_gen_signaturehexbinary.ReadOnly = true;
            this.hmac_gen_signaturehexbinary.Size = new System.Drawing.Size(1867, 215);
            this.hmac_gen_signaturehexbinary.TabIndex = 28;
            this.hmac_gen_signaturehexbinary.TabStop = false;
            // 
            // groupBox16
            // 
            this.groupBox16.BackColor = System.Drawing.SystemColors.ControlLight;
            this.groupBox16.Controls.Add(this.hmac_gen_defsk);
            this.groupBox16.Controls.Add(this.hmac_gen_sk);
            this.groupBox16.Controls.Add(this.label30);
            this.groupBox16.Controls.Add(this.hmac_gen_sha512);
            this.groupBox16.Controls.Add(this.hmac_gen_sha256);
            this.groupBox16.Controls.Add(this.label28);
            this.groupBox16.Controls.Add(this.hmac_gen_reset);
            this.groupBox16.Controls.Add(this.hmac_gen_generator);
            this.groupBox16.Controls.Add(this.hmac_gen_msg);
            this.groupBox16.Controls.Add(this.label29);
            this.groupBox16.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox16.Location = new System.Drawing.Point(16, 14);
            this.groupBox16.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox16.Name = "groupBox16";
            this.groupBox16.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox16.Size = new System.Drawing.Size(3099, 589);
            this.groupBox16.TabIndex = 10;
            this.groupBox16.TabStop = false;
            this.groupBox16.Text = "Input";
            // 
            // hmac_gen_defsk
            // 
            this.hmac_gen_defsk.AutoSize = true;
            this.hmac_gen_defsk.Checked = true;
            this.hmac_gen_defsk.CheckState = System.Windows.Forms.CheckState.Checked;
            this.hmac_gen_defsk.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_gen_defsk.Location = new System.Drawing.Point(1448, 153);
            this.hmac_gen_defsk.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_gen_defsk.Name = "hmac_gen_defsk";
            this.hmac_gen_defsk.Size = new System.Drawing.Size(332, 50);
            this.hmac_gen_defsk.TabIndex = 28;
            this.hmac_gen_defsk.Text = "Use default key";
            this.hmac_gen_defsk.UseVisualStyleBackColor = true;
            this.hmac_gen_defsk.CheckedChanged += new System.EventHandler(this.hmac_gen_defsk_CheckedChanged);
            // 
            // hmac_gen_sk
            // 
            this.hmac_gen_sk.Enabled = false;
            this.hmac_gen_sk.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_gen_sk.Location = new System.Drawing.Point(461, 153);
            this.hmac_gen_sk.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_gen_sk.Name = "hmac_gen_sk";
            this.hmac_gen_sk.Size = new System.Drawing.Size(964, 53);
            this.hmac_gen_sk.TabIndex = 27;
            // 
            // label30
            // 
            this.label30.AutoSize = true;
            this.label30.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label30.Location = new System.Drawing.Point(8, 160);
            this.label30.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label30.Name = "label30";
            this.label30.Size = new System.Drawing.Size(215, 46);
            this.label30.TabIndex = 26;
            this.label30.Text = "Secret Key";
            // 
            // hmac_gen_sha512
            // 
            this.hmac_gen_sha512.AutoSize = true;
            this.hmac_gen_sha512.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_gen_sha512.Location = new System.Drawing.Point(744, 246);
            this.hmac_gen_sha512.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_gen_sha512.Name = "hmac_gen_sha512";
            this.hmac_gen_sha512.Size = new System.Drawing.Size(206, 50);
            this.hmac_gen_sha512.TabIndex = 25;
            this.hmac_gen_sha512.Text = "SHA512";
            this.hmac_gen_sha512.UseVisualStyleBackColor = true;
            // 
            // hmac_gen_sha256
            // 
            this.hmac_gen_sha256.AutoSize = true;
            this.hmac_gen_sha256.Checked = true;
            this.hmac_gen_sha256.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_gen_sha256.Location = new System.Drawing.Point(461, 246);
            this.hmac_gen_sha256.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_gen_sha256.Name = "hmac_gen_sha256";
            this.hmac_gen_sha256.Size = new System.Drawing.Size(206, 50);
            this.hmac_gen_sha256.TabIndex = 24;
            this.hmac_gen_sha256.TabStop = true;
            this.hmac_gen_sha256.Text = "SHA256";
            this.hmac_gen_sha256.UseVisualStyleBackColor = true;
            // 
            // label28
            // 
            this.label28.AutoSize = true;
            this.label28.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label28.Location = new System.Drawing.Point(16, 255);
            this.label28.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label28.Name = "label28";
            this.label28.Size = new System.Drawing.Size(293, 46);
            this.label28.TabIndex = 22;
            this.label28.Text = "Hash Algorithm";
            // 
            // hmac_gen_reset
            // 
            this.hmac_gen_reset.BackColor = System.Drawing.SystemColors.ControlDark;
            this.hmac_gen_reset.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.hmac_gen_reset.Location = new System.Drawing.Point(2667, 48);
            this.hmac_gen_reset.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_gen_reset.Name = "hmac_gen_reset";
            this.hmac_gen_reset.Size = new System.Drawing.Size(400, 79);
            this.hmac_gen_reset.TabIndex = 21;
            this.hmac_gen_reset.Text = "Reset";
            this.hmac_gen_reset.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.hmac_gen_reset.UseVisualStyleBackColor = false;
            this.hmac_gen_reset.Click += new System.EventHandler(this.hmac_gen_reset_Click);
            // 
            // hmac_gen_generator
            // 
            this.hmac_gen_generator.BackColor = System.Drawing.SystemColors.ControlDark;
            this.hmac_gen_generator.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.hmac_gen_generator.Location = new System.Drawing.Point(2667, 143);
            this.hmac_gen_generator.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_gen_generator.Name = "hmac_gen_generator";
            this.hmac_gen_generator.Size = new System.Drawing.Size(400, 79);
            this.hmac_gen_generator.TabIndex = 18;
            this.hmac_gen_generator.Text = "Generate";
            this.hmac_gen_generator.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.hmac_gen_generator.UseVisualStyleBackColor = false;
            this.hmac_gen_generator.Click += new System.EventHandler(this.hmac_gen_generator_Click);
            // 
            // hmac_gen_msg
            // 
            this.hmac_gen_msg.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_gen_msg.Location = new System.Drawing.Point(461, 67);
            this.hmac_gen_msg.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_gen_msg.Name = "hmac_gen_msg";
            this.hmac_gen_msg.Size = new System.Drawing.Size(1660, 53);
            this.hmac_gen_msg.TabIndex = 15;
            // 
            // label29
            // 
            this.label29.AutoSize = true;
            this.label29.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label29.Location = new System.Drawing.Point(8, 74);
            this.label29.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label29.Name = "label29";
            this.label29.Size = new System.Drawing.Size(421, 46);
            this.label29.TabIndex = 12;
            this.label29.Text = "Message(Include pipe)";
            // 
            // tabPage7
            // 
            this.tabPage7.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage7.Controls.Add(this.groupBox17);
            this.tabPage7.Controls.Add(this.groupBox18);
            this.tabPage7.Location = new System.Drawing.Point(10, 28);
            this.tabPage7.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage7.Name = "tabPage7";
            this.tabPage7.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage7.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage7.TabIndex = 7;
            this.tabPage7.Text = "HMAC Verification";
            // 
            // groupBox17
            // 
            this.groupBox17.BackColor = System.Drawing.SystemColors.ControlLight;
            this.groupBox17.Controls.Add(this.label27);
            this.groupBox17.Controls.Add(this.hmac_ver_signresult);
            this.groupBox17.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox17.Location = new System.Drawing.Point(16, 618);
            this.groupBox17.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox17.Name = "groupBox17";
            this.groupBox17.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox17.Size = new System.Drawing.Size(3099, 310);
            this.groupBox17.TabIndex = 13;
            this.groupBox17.TabStop = false;
            this.groupBox17.Text = "Signature";
            // 
            // label27
            // 
            this.label27.AutoSize = true;
            this.label27.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label27.Location = new System.Drawing.Point(13, 72);
            this.label27.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label27.Name = "label27";
            this.label27.Size = new System.Drawing.Size(155, 46);
            this.label27.TabIndex = 30;
            this.label27.Text = "Verified";
            // 
            // hmac_ver_signresult
            // 
            this.hmac_ver_signresult.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.hmac_ver_signresult.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_ver_signresult.Location = new System.Drawing.Point(251, 72);
            this.hmac_ver_signresult.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_signresult.Multiline = true;
            this.hmac_ver_signresult.Name = "hmac_ver_signresult";
            this.hmac_ver_signresult.ReadOnly = true;
            this.hmac_ver_signresult.Size = new System.Drawing.Size(475, 62);
            this.hmac_ver_signresult.TabIndex = 1;
            this.hmac_ver_signresult.TabStop = false;
            // 
            // groupBox18
            // 
            this.groupBox18.BackColor = System.Drawing.SystemColors.ControlLight;
            this.groupBox18.Controls.Add(this.hmac_ver_signature);
            this.groupBox18.Controls.Add(this.label34);
            this.groupBox18.Controls.Add(this.hmac_ver_defsk);
            this.groupBox18.Controls.Add(this.hmac_ver_sk);
            this.groupBox18.Controls.Add(this.label26);
            this.groupBox18.Controls.Add(this.hmac_ver_sha512);
            this.groupBox18.Controls.Add(this.hmac_ver_sha256);
            this.groupBox18.Controls.Add(this.label32);
            this.groupBox18.Controls.Add(this.hmac_ver_msg);
            this.groupBox18.Controls.Add(this.label33);
            this.groupBox18.Controls.Add(this.hmac_ver_reset);
            this.groupBox18.Controls.Add(this.hmac_ver_generator);
            this.groupBox18.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox18.Location = new System.Drawing.Point(16, 14);
            this.groupBox18.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox18.Name = "groupBox18";
            this.groupBox18.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox18.Size = new System.Drawing.Size(3099, 589);
            this.groupBox18.TabIndex = 12;
            this.groupBox18.TabStop = false;
            this.groupBox18.Text = "Input";
            // 
            // hmac_ver_signature
            // 
            this.hmac_ver_signature.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_ver_signature.Location = new System.Drawing.Point(461, 317);
            this.hmac_ver_signature.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_signature.Multiline = true;
            this.hmac_ver_signature.Name = "hmac_ver_signature";
            this.hmac_ver_signature.Size = new System.Drawing.Size(1660, 252);
            this.hmac_ver_signature.TabIndex = 38;
            // 
            // label34
            // 
            this.label34.AutoSize = true;
            this.label34.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label34.Location = new System.Drawing.Point(16, 324);
            this.label34.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label34.Name = "label34";
            this.label34.Size = new System.Drawing.Size(401, 46);
            this.label34.TabIndex = 37;
            this.label34.Text = "Signature(HexBinary)";
            // 
            // hmac_ver_defsk
            // 
            this.hmac_ver_defsk.AutoSize = true;
            this.hmac_ver_defsk.Checked = true;
            this.hmac_ver_defsk.CheckState = System.Windows.Forms.CheckState.Checked;
            this.hmac_ver_defsk.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_ver_defsk.Location = new System.Drawing.Point(1448, 153);
            this.hmac_ver_defsk.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_defsk.Name = "hmac_ver_defsk";
            this.hmac_ver_defsk.Size = new System.Drawing.Size(332, 50);
            this.hmac_ver_defsk.TabIndex = 36;
            this.hmac_ver_defsk.Text = "Use default key";
            this.hmac_ver_defsk.UseVisualStyleBackColor = true;
            this.hmac_ver_defsk.CheckedChanged += new System.EventHandler(this.hmac_ver_defsk_CheckedChanged);
            // 
            // hmac_ver_sk
            // 
            this.hmac_ver_sk.Enabled = false;
            this.hmac_ver_sk.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_ver_sk.Location = new System.Drawing.Point(461, 153);
            this.hmac_ver_sk.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_sk.Name = "hmac_ver_sk";
            this.hmac_ver_sk.Size = new System.Drawing.Size(964, 53);
            this.hmac_ver_sk.TabIndex = 35;
            // 
            // label26
            // 
            this.label26.AutoSize = true;
            this.label26.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label26.Location = new System.Drawing.Point(8, 160);
            this.label26.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label26.Name = "label26";
            this.label26.Size = new System.Drawing.Size(215, 46);
            this.label26.TabIndex = 34;
            this.label26.Text = "Secret Key";
            // 
            // hmac_ver_sha512
            // 
            this.hmac_ver_sha512.AutoSize = true;
            this.hmac_ver_sha512.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_ver_sha512.Location = new System.Drawing.Point(744, 246);
            this.hmac_ver_sha512.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_sha512.Name = "hmac_ver_sha512";
            this.hmac_ver_sha512.Size = new System.Drawing.Size(206, 50);
            this.hmac_ver_sha512.TabIndex = 33;
            this.hmac_ver_sha512.Text = "SHA512";
            this.hmac_ver_sha512.UseVisualStyleBackColor = true;
            // 
            // hmac_ver_sha256
            // 
            this.hmac_ver_sha256.AutoSize = true;
            this.hmac_ver_sha256.Checked = true;
            this.hmac_ver_sha256.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_ver_sha256.Location = new System.Drawing.Point(461, 246);
            this.hmac_ver_sha256.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_sha256.Name = "hmac_ver_sha256";
            this.hmac_ver_sha256.Size = new System.Drawing.Size(206, 50);
            this.hmac_ver_sha256.TabIndex = 32;
            this.hmac_ver_sha256.TabStop = true;
            this.hmac_ver_sha256.Text = "SHA256";
            this.hmac_ver_sha256.UseVisualStyleBackColor = true;
            // 
            // label32
            // 
            this.label32.AutoSize = true;
            this.label32.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label32.Location = new System.Drawing.Point(16, 255);
            this.label32.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label32.Name = "label32";
            this.label32.Size = new System.Drawing.Size(293, 46);
            this.label32.TabIndex = 31;
            this.label32.Text = "Hash Algorithm";
            // 
            // hmac_ver_msg
            // 
            this.hmac_ver_msg.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.hmac_ver_msg.Location = new System.Drawing.Point(461, 67);
            this.hmac_ver_msg.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_msg.Name = "hmac_ver_msg";
            this.hmac_ver_msg.Size = new System.Drawing.Size(1660, 53);
            this.hmac_ver_msg.TabIndex = 30;
            // 
            // label33
            // 
            this.label33.AutoSize = true;
            this.label33.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label33.Location = new System.Drawing.Point(8, 74);
            this.label33.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label33.Name = "label33";
            this.label33.Size = new System.Drawing.Size(421, 46);
            this.label33.TabIndex = 29;
            this.label33.Text = "Message(Include pipe)";
            // 
            // hmac_ver_reset
            // 
            this.hmac_ver_reset.BackColor = System.Drawing.SystemColors.ControlDark;
            this.hmac_ver_reset.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.hmac_ver_reset.Location = new System.Drawing.Point(2667, 48);
            this.hmac_ver_reset.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_reset.Name = "hmac_ver_reset";
            this.hmac_ver_reset.Size = new System.Drawing.Size(400, 79);
            this.hmac_ver_reset.TabIndex = 21;
            this.hmac_ver_reset.Text = "Reset";
            this.hmac_ver_reset.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.hmac_ver_reset.UseVisualStyleBackColor = false;
            this.hmac_ver_reset.Click += new System.EventHandler(this.hmac_ver_reset_Click);
            // 
            // hmac_ver_generator
            // 
            this.hmac_ver_generator.BackColor = System.Drawing.SystemColors.ControlDark;
            this.hmac_ver_generator.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.hmac_ver_generator.Location = new System.Drawing.Point(2667, 143);
            this.hmac_ver_generator.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.hmac_ver_generator.Name = "hmac_ver_generator";
            this.hmac_ver_generator.Size = new System.Drawing.Size(400, 79);
            this.hmac_ver_generator.TabIndex = 18;
            this.hmac_ver_generator.Text = "Verify";
            this.hmac_ver_generator.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.hmac_ver_generator.UseVisualStyleBackColor = false;
            this.hmac_ver_generator.Click += new System.EventHandler(this.hmac_ver_generator_Click);
            // 
            // PlainTextEncrypt
            // 
            this.PlainTextEncrypt.BackColor = System.Drawing.SystemColors.ControlLight;
            this.PlainTextEncrypt.Controls.Add(this.groupBox19);
            this.PlainTextEncrypt.Controls.Add(this.groupBox20);
            this.PlainTextEncrypt.Location = new System.Drawing.Point(10, 28);
            this.PlainTextEncrypt.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.PlainTextEncrypt.Name = "PlainTextEncrypt";
            this.PlainTextEncrypt.Padding = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.PlainTextEncrypt.Size = new System.Drawing.Size(3137, 1278);
            this.PlainTextEncrypt.TabIndex = 8;
            this.PlainTextEncrypt.Text = "Plain Text Encrypt";
            // 
            // groupBox19
            // 
            this.groupBox19.BackColor = System.Drawing.SystemColors.ControlLight;
            this.groupBox19.Controls.Add(this.plainText_enc_result);
            this.groupBox19.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox19.Location = new System.Drawing.Point(19, 525);
            this.groupBox19.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox19.Name = "groupBox19";
            this.groupBox19.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox19.Size = new System.Drawing.Size(3096, 715);
            this.groupBox19.TabIndex = 13;
            this.groupBox19.TabStop = false;
            this.groupBox19.Text = "Result";
            // 
            // plainText_enc_result
            // 
            this.plainText_enc_result.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.plainText_enc_result.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_enc_result.Location = new System.Drawing.Point(16, 74);
            this.plainText_enc_result.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_result.MaxLength = 100000;
            this.plainText_enc_result.Multiline = true;
            this.plainText_enc_result.Name = "plainText_enc_result";
            this.plainText_enc_result.ReadOnly = true;
            this.plainText_enc_result.Size = new System.Drawing.Size(3064, 525);
            this.plainText_enc_result.TabIndex = 28;
            this.plainText_enc_result.TabStop = false;
            // 
            // groupBox20
            // 
            this.groupBox20.BackColor = System.Drawing.SystemColors.ControlLight;
            this.groupBox20.Controls.Add(this.plainText_enc_ggit_wallet_library_setting);
            this.groupBox20.Controls.Add(this.plainText_enc_allow_fileinput);
            this.groupBox20.Controls.Add(this.plainText_enc_msg_input);
            this.groupBox20.Controls.Add(this.plainText_enc_generator);
            this.groupBox20.Controls.Add(this.plainText_enc_upload);
            this.groupBox20.Controls.Add(this.plainText_enc_defkey);
            this.groupBox20.Controls.Add(this.plainText_enc_sk_input);
            this.groupBox20.Controls.Add(this.label35);
            this.groupBox20.Controls.Add(this.plainText_enc_reset);
            this.groupBox20.Controls.Add(this.label37);
            this.groupBox20.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox20.Location = new System.Drawing.Point(19, 19);
            this.groupBox20.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox20.Name = "groupBox20";
            this.groupBox20.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox20.Size = new System.Drawing.Size(3096, 496);
            this.groupBox20.TabIndex = 12;
            this.groupBox20.TabStop = false;
            this.groupBox20.Text = "Input";
            // 
            // plainText_enc_ggit_wallet_library_setting
            // 
            this.plainText_enc_ggit_wallet_library_setting.AutoSize = true;
            this.plainText_enc_ggit_wallet_library_setting.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_enc_ggit_wallet_library_setting.Location = new System.Drawing.Point(1867, 291);
            this.plainText_enc_ggit_wallet_library_setting.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_ggit_wallet_library_setting.Name = "plainText_enc_ggit_wallet_library_setting";
            this.plainText_enc_ggit_wallet_library_setting.Size = new System.Drawing.Size(621, 50);
            this.plainText_enc_ggit_wallet_library_setting.TabIndex = 47;
            this.plainText_enc_ggit_wallet_library_setting.Text = "GGIT Wallet Encryption method";
            this.plainText_enc_ggit_wallet_library_setting.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.plainText_enc_ggit_wallet_library_setting.UseVisualStyleBackColor = true;
            this.plainText_enc_ggit_wallet_library_setting.CheckedChanged += new System.EventHandler(this.plainText_enc_ggit_wallet_library_setting_CheckedChanged);
            // 
            // plainText_enc_allow_fileinput
            // 
            this.plainText_enc_allow_fileinput.AutoSize = true;
            this.plainText_enc_allow_fileinput.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_enc_allow_fileinput.Location = new System.Drawing.Point(2797, 72);
            this.plainText_enc_allow_fileinput.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_allow_fileinput.Name = "plainText_enc_allow_fileinput";
            this.plainText_enc_allow_fileinput.Size = new System.Drawing.Size(220, 50);
            this.plainText_enc_allow_fileinput.TabIndex = 46;
            this.plainText_enc_allow_fileinput.Text = "File Input";
            this.plainText_enc_allow_fileinput.UseVisualStyleBackColor = true;
            this.plainText_enc_allow_fileinput.CheckedChanged += new System.EventHandler(this.plainText_enc_allow_fileinput_CheckedChanged);
            // 
            // plainText_enc_msg_input
            // 
            this.plainText_enc_msg_input.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_enc_msg_input.Location = new System.Drawing.Point(267, 72);
            this.plainText_enc_msg_input.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_msg_input.MaxLength = 100000;
            this.plainText_enc_msg_input.Multiline = true;
            this.plainText_enc_msg_input.Name = "plainText_enc_msg_input";
            this.plainText_enc_msg_input.Size = new System.Drawing.Size(2508, 185);
            this.plainText_enc_msg_input.TabIndex = 45;
            // 
            // plainText_enc_generator
            // 
            this.plainText_enc_generator.BackColor = System.Drawing.SystemColors.ControlDark;
            this.plainText_enc_generator.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.plainText_enc_generator.Location = new System.Drawing.Point(2680, 379);
            this.plainText_enc_generator.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_generator.Name = "plainText_enc_generator";
            this.plainText_enc_generator.Size = new System.Drawing.Size(400, 79);
            this.plainText_enc_generator.TabIndex = 41;
            this.plainText_enc_generator.Text = "Generate";
            this.plainText_enc_generator.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.plainText_enc_generator.UseVisualStyleBackColor = false;
            this.plainText_enc_generator.Click += new System.EventHandler(this.plainText_enc_generator_Click);
            // 
            // plainText_enc_upload
            // 
            this.plainText_enc_upload.BackColor = System.Drawing.SystemColors.ActiveBorder;
            this.plainText_enc_upload.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.plainText_enc_upload.Enabled = false;
            this.plainText_enc_upload.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F);
            this.plainText_enc_upload.Location = new System.Drawing.Point(1848, 379);
            this.plainText_enc_upload.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_upload.Name = "plainText_enc_upload";
            this.plainText_enc_upload.Size = new System.Drawing.Size(400, 79);
            this.plainText_enc_upload.TabIndex = 38;
            this.plainText_enc_upload.Text = "Input a json file...";
            this.plainText_enc_upload.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.plainText_enc_upload.UseVisualStyleBackColor = false;
            this.plainText_enc_upload.Click += new System.EventHandler(this.plainText_enc_upload_Click);
            // 
            // plainText_enc_defkey
            // 
            this.plainText_enc_defkey.AutoSize = true;
            this.plainText_enc_defkey.Checked = true;
            this.plainText_enc_defkey.CheckState = System.Windows.Forms.CheckState.Checked;
            this.plainText_enc_defkey.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_enc_defkey.Location = new System.Drawing.Point(1483, 291);
            this.plainText_enc_defkey.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_defkey.Name = "plainText_enc_defkey";
            this.plainText_enc_defkey.Size = new System.Drawing.Size(332, 50);
            this.plainText_enc_defkey.TabIndex = 37;
            this.plainText_enc_defkey.Text = "Use default key";
            this.plainText_enc_defkey.UseVisualStyleBackColor = true;
            this.plainText_enc_defkey.CheckedChanged += new System.EventHandler(this.plainText_enc_defkey_CheckedChanged);
            // 
            // plainText_enc_sk_input
            // 
            this.plainText_enc_sk_input.Enabled = false;
            this.plainText_enc_sk_input.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_enc_sk_input.Location = new System.Drawing.Point(267, 286);
            this.plainText_enc_sk_input.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_sk_input.Name = "plainText_enc_sk_input";
            this.plainText_enc_sk_input.Size = new System.Drawing.Size(1193, 53);
            this.plainText_enc_sk_input.TabIndex = 27;
            // 
            // label35
            // 
            this.label35.AutoSize = true;
            this.label35.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label35.Location = new System.Drawing.Point(16, 286);
            this.label35.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label35.Name = "label35";
            this.label35.Size = new System.Drawing.Size(215, 46);
            this.label35.TabIndex = 26;
            this.label35.Text = "Secret Key";
            // 
            // plainText_enc_reset
            // 
            this.plainText_enc_reset.BackColor = System.Drawing.SystemColors.ControlDark;
            this.plainText_enc_reset.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.plainText_enc_reset.Location = new System.Drawing.Point(2264, 379);
            this.plainText_enc_reset.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_enc_reset.Name = "plainText_enc_reset";
            this.plainText_enc_reset.Size = new System.Drawing.Size(400, 79);
            this.plainText_enc_reset.TabIndex = 21;
            this.plainText_enc_reset.Text = "Reset";
            this.plainText_enc_reset.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.plainText_enc_reset.UseVisualStyleBackColor = false;
            this.plainText_enc_reset.Click += new System.EventHandler(this.plainText_enc_reset_Click);
            // 
            // label37
            // 
            this.label37.AutoSize = true;
            this.label37.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label37.Location = new System.Drawing.Point(16, 72);
            this.label37.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label37.Name = "label37";
            this.label37.Size = new System.Drawing.Size(198, 46);
            this.label37.TabIndex = 12;
            this.label37.Text = "Plain Text";
            // 
            // tabPage8
            // 
            this.tabPage8.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage8.Controls.Add(this.groupBox21);
            this.tabPage8.Controls.Add(this.groupBox22);
            this.tabPage8.Location = new System.Drawing.Point(10, 28);
            this.tabPage8.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.tabPage8.Name = "tabPage8";
            this.tabPage8.Padding = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.tabPage8.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage8.TabIndex = 9;
            this.tabPage8.Text = "Plain Text Decrypt";
            // 
            // groupBox21
            // 
            this.groupBox21.BackColor = System.Drawing.SystemColors.ControlLight;
            this.groupBox21.Controls.Add(this.plainText_dec_result);
            this.groupBox21.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox21.Location = new System.Drawing.Point(19, 525);
            this.groupBox21.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox21.Name = "groupBox21";
            this.groupBox21.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox21.Size = new System.Drawing.Size(3096, 715);
            this.groupBox21.TabIndex = 15;
            this.groupBox21.TabStop = false;
            this.groupBox21.Text = "Result";
            // 
            // plainText_dec_result
            // 
            this.plainText_dec_result.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.plainText_dec_result.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_dec_result.Location = new System.Drawing.Point(16, 74);
            this.plainText_dec_result.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_result.MaxLength = 100000;
            this.plainText_dec_result.Multiline = true;
            this.plainText_dec_result.Name = "plainText_dec_result";
            this.plainText_dec_result.ReadOnly = true;
            this.plainText_dec_result.Size = new System.Drawing.Size(3064, 525);
            this.plainText_dec_result.TabIndex = 28;
            this.plainText_dec_result.TabStop = false;
            // 
            // groupBox22
            // 
            this.groupBox22.BackColor = System.Drawing.SystemColors.ControlLight;
            this.groupBox22.Controls.Add(this.plainText_dec_ggit_wallet_library_setting);
            this.groupBox22.Controls.Add(this.plainText_dec_upload);
            this.groupBox22.Controls.Add(this.plainText_dec_allow_fileinput);
            this.groupBox22.Controls.Add(this.plainText_dec_msg_input);
            this.groupBox22.Controls.Add(this.plainText_dec_generator);
            this.groupBox22.Controls.Add(this.label39);
            this.groupBox22.Controls.Add(this.plainText_dec_defkey);
            this.groupBox22.Controls.Add(this.plainText_dec_sk_input);
            this.groupBox22.Controls.Add(this.label38);
            this.groupBox22.Controls.Add(this.plainText_dec_reset);
            this.groupBox22.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox22.Location = new System.Drawing.Point(19, 19);
            this.groupBox22.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox22.Name = "groupBox22";
            this.groupBox22.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.groupBox22.Size = new System.Drawing.Size(3096, 496);
            this.groupBox22.TabIndex = 14;
            this.groupBox22.TabStop = false;
            this.groupBox22.Text = "Input";
            // 
            // plainText_dec_ggit_wallet_library_setting
            // 
            this.plainText_dec_ggit_wallet_library_setting.AutoSize = true;
            this.plainText_dec_ggit_wallet_library_setting.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_dec_ggit_wallet_library_setting.Location = new System.Drawing.Point(1867, 291);
            this.plainText_dec_ggit_wallet_library_setting.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_ggit_wallet_library_setting.Name = "plainText_dec_ggit_wallet_library_setting";
            this.plainText_dec_ggit_wallet_library_setting.Size = new System.Drawing.Size(621, 50);
            this.plainText_dec_ggit_wallet_library_setting.TabIndex = 50;
            this.plainText_dec_ggit_wallet_library_setting.Text = "GGIT Wallet Encryption method";
            this.plainText_dec_ggit_wallet_library_setting.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.plainText_dec_ggit_wallet_library_setting.UseVisualStyleBackColor = true;
            this.plainText_dec_ggit_wallet_library_setting.CheckedChanged += new System.EventHandler(this.plainText_dec_ggit_wallet_library_setting_CheckedChanged);
            // 
            // plainText_dec_upload
            // 
            this.plainText_dec_upload.BackColor = System.Drawing.SystemColors.ActiveBorder;
            this.plainText_dec_upload.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.plainText_dec_upload.Enabled = false;
            this.plainText_dec_upload.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F);
            this.plainText_dec_upload.Location = new System.Drawing.Point(1848, 379);
            this.plainText_dec_upload.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_upload.Name = "plainText_dec_upload";
            this.plainText_dec_upload.Size = new System.Drawing.Size(400, 79);
            this.plainText_dec_upload.TabIndex = 49;
            this.plainText_dec_upload.Text = "Input a json file...";
            this.plainText_dec_upload.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.plainText_dec_upload.UseVisualStyleBackColor = false;
            this.plainText_dec_upload.Click += new System.EventHandler(this.plainText_dec_upload_Click);
            // 
            // plainText_dec_allow_fileinput
            // 
            this.plainText_dec_allow_fileinput.AutoSize = true;
            this.plainText_dec_allow_fileinput.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_dec_allow_fileinput.Location = new System.Drawing.Point(2797, 72);
            this.plainText_dec_allow_fileinput.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_allow_fileinput.Name = "plainText_dec_allow_fileinput";
            this.plainText_dec_allow_fileinput.Size = new System.Drawing.Size(220, 50);
            this.plainText_dec_allow_fileinput.TabIndex = 47;
            this.plainText_dec_allow_fileinput.Text = "File Input";
            this.plainText_dec_allow_fileinput.UseVisualStyleBackColor = true;
            this.plainText_dec_allow_fileinput.CheckedChanged += new System.EventHandler(this.plainText_dec_allow_fileinput_CheckedChanged);
            // 
            // plainText_dec_msg_input
            // 
            this.plainText_dec_msg_input.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_dec_msg_input.Location = new System.Drawing.Point(267, 72);
            this.plainText_dec_msg_input.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_msg_input.MaxLength = 100000;
            this.plainText_dec_msg_input.Multiline = true;
            this.plainText_dec_msg_input.Name = "plainText_dec_msg_input";
            this.plainText_dec_msg_input.Size = new System.Drawing.Size(2508, 185);
            this.plainText_dec_msg_input.TabIndex = 44;
            // 
            // plainText_dec_generator
            // 
            this.plainText_dec_generator.BackColor = System.Drawing.SystemColors.ControlDark;
            this.plainText_dec_generator.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.plainText_dec_generator.Location = new System.Drawing.Point(2680, 379);
            this.plainText_dec_generator.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_generator.Name = "plainText_dec_generator";
            this.plainText_dec_generator.Size = new System.Drawing.Size(400, 79);
            this.plainText_dec_generator.TabIndex = 43;
            this.plainText_dec_generator.Text = "Generate";
            this.plainText_dec_generator.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.plainText_dec_generator.UseVisualStyleBackColor = false;
            this.plainText_dec_generator.Click += new System.EventHandler(this.plainText_dec_generator_Click_1);
            // 
            // label39
            // 
            this.label39.AutoSize = true;
            this.label39.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label39.Location = new System.Drawing.Point(16, 72);
            this.label39.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label39.Name = "label39";
            this.label39.Size = new System.Drawing.Size(226, 46);
            this.label39.TabIndex = 41;
            this.label39.Text = "Cipher Text";
            // 
            // plainText_dec_defkey
            // 
            this.plainText_dec_defkey.AutoSize = true;
            this.plainText_dec_defkey.Checked = true;
            this.plainText_dec_defkey.CheckState = System.Windows.Forms.CheckState.Checked;
            this.plainText_dec_defkey.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_dec_defkey.Location = new System.Drawing.Point(1483, 291);
            this.plainText_dec_defkey.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_defkey.Name = "plainText_dec_defkey";
            this.plainText_dec_defkey.Size = new System.Drawing.Size(332, 50);
            this.plainText_dec_defkey.TabIndex = 37;
            this.plainText_dec_defkey.Text = "Use default key";
            this.plainText_dec_defkey.UseVisualStyleBackColor = true;
            this.plainText_dec_defkey.CheckedChanged += new System.EventHandler(this.plainText_dec_defkey_CheckedChanged);
            // 
            // plainText_dec_sk_input
            // 
            this.plainText_dec_sk_input.Enabled = false;
            this.plainText_dec_sk_input.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.plainText_dec_sk_input.Location = new System.Drawing.Point(267, 286);
            this.plainText_dec_sk_input.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_sk_input.Name = "plainText_dec_sk_input";
            this.plainText_dec_sk_input.Size = new System.Drawing.Size(1193, 53);
            this.plainText_dec_sk_input.TabIndex = 33;
            // 
            // label38
            // 
            this.label38.AutoSize = true;
            this.label38.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label38.Location = new System.Drawing.Point(16, 286);
            this.label38.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.label38.Name = "label38";
            this.label38.Size = new System.Drawing.Size(215, 46);
            this.label38.TabIndex = 32;
            this.label38.Text = "Secret Key";
            // 
            // plainText_dec_reset
            // 
            this.plainText_dec_reset.BackColor = System.Drawing.SystemColors.ControlDark;
            this.plainText_dec_reset.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.plainText_dec_reset.Location = new System.Drawing.Point(2264, 379);
            this.plainText_dec_reset.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.plainText_dec_reset.Name = "plainText_dec_reset";
            this.plainText_dec_reset.Size = new System.Drawing.Size(400, 79);
            this.plainText_dec_reset.TabIndex = 31;
            this.plainText_dec_reset.Text = "Reset";
            this.plainText_dec_reset.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.plainText_dec_reset.UseVisualStyleBackColor = false;
            this.plainText_dec_reset.Click += new System.EventHandler(this.plainText_dec_reset_Click);
            // 
            // tabPage9
            // 
            this.tabPage9.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage9.Controls.Add(this.rsa_encryptor_result_group);
            this.tabPage9.Controls.Add(this.rsa_encryptor_input_group);
            this.tabPage9.Location = new System.Drawing.Point(10, 28);
            this.tabPage9.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage9.Name = "tabPage9";
            this.tabPage9.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage9.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage9.TabIndex = 10;
            this.tabPage9.Text = "RSA Encryptor";
            // 
            // rsa_encryptor_result_group
            // 
            this.rsa_encryptor_result_group.BackColor = System.Drawing.SystemColors.ControlLight;
            this.rsa_encryptor_result_group.Controls.Add(this.rsa_encryptor_result_output);
            this.rsa_encryptor_result_group.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_encryptor_result_group.Location = new System.Drawing.Point(8, 596);
            this.rsa_encryptor_result_group.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_encryptor_result_group.Name = "rsa_encryptor_result_group";
            this.rsa_encryptor_result_group.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_encryptor_result_group.Size = new System.Drawing.Size(3107, 644);
            this.rsa_encryptor_result_group.TabIndex = 14;
            this.rsa_encryptor_result_group.TabStop = false;
            this.rsa_encryptor_result_group.Text = "Result";
            // 
            // rsa_encryptor_result_output
            // 
            this.rsa_encryptor_result_output.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.rsa_encryptor_result_output.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_encryptor_result_output.Location = new System.Drawing.Point(40, 72);
            this.rsa_encryptor_result_output.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_encryptor_result_output.Multiline = true;
            this.rsa_encryptor_result_output.Name = "rsa_encryptor_result_output";
            this.rsa_encryptor_result_output.ReadOnly = true;
            this.rsa_encryptor_result_output.Size = new System.Drawing.Size(2611, 539);
            this.rsa_encryptor_result_output.TabIndex = 28;
            this.rsa_encryptor_result_output.TabStop = false;
            // 
            // rsa_encryptor_input_group
            // 
            this.rsa_encryptor_input_group.Controls.Add(this.rsa_encryptor_dropdown);
            this.rsa_encryptor_input_group.Controls.Add(this.allowed_Encoded);
            this.rsa_encryptor_input_group.Controls.Add(this.rsa_encryptor_plain_input);
            this.rsa_encryptor_input_group.Controls.Add(this.rsa_encryptor_reset);
            this.rsa_encryptor_input_group.Controls.Add(this.rsa_encryptor_plain_label);
            this.rsa_encryptor_input_group.Controls.Add(this.rsa_encryptor_encrypt);
            this.rsa_encryptor_input_group.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_encryptor_input_group.Location = new System.Drawing.Point(8, 14);
            this.rsa_encryptor_input_group.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_encryptor_input_group.Name = "rsa_encryptor_input_group";
            this.rsa_encryptor_input_group.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_encryptor_input_group.Size = new System.Drawing.Size(3107, 568);
            this.rsa_encryptor_input_group.TabIndex = 5;
            this.rsa_encryptor_input_group.TabStop = false;
            this.rsa_encryptor_input_group.Text = "Input";
            // 
            // allowed_Encoded
            // 
            this.allowed_Encoded.AutoSize = true;
            this.allowed_Encoded.Location = new System.Drawing.Point(2667, 250);
            this.allowed_Encoded.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.allowed_Encoded.Name = "allowed_Encoded";
            this.allowed_Encoded.Size = new System.Drawing.Size(226, 59);
            this.allowed_Encoded.TabIndex = 46;
            this.allowed_Encoded.Text = "Encode";
            this.allowed_Encoded.UseVisualStyleBackColor = true;
            // 
            // rsa_encryptor_plain_input
            // 
            this.rsa_encryptor_plain_input.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_encryptor_plain_input.Location = new System.Drawing.Point(320, 57);
            this.rsa_encryptor_plain_input.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_encryptor_plain_input.Multiline = true;
            this.rsa_encryptor_plain_input.Name = "rsa_encryptor_plain_input";
            this.rsa_encryptor_plain_input.Size = new System.Drawing.Size(2324, 471);
            this.rsa_encryptor_plain_input.TabIndex = 45;
            // 
            // rsa_encryptor_reset
            // 
            this.rsa_encryptor_reset.BackColor = System.Drawing.SystemColors.ControlDark;
            this.rsa_encryptor_reset.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.rsa_encryptor_reset.Location = new System.Drawing.Point(2667, 48);
            this.rsa_encryptor_reset.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_encryptor_reset.Name = "rsa_encryptor_reset";
            this.rsa_encryptor_reset.Size = new System.Drawing.Size(400, 79);
            this.rsa_encryptor_reset.TabIndex = 20;
            this.rsa_encryptor_reset.Text = "Reset";
            this.rsa_encryptor_reset.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.rsa_encryptor_reset.UseVisualStyleBackColor = false;
            this.rsa_encryptor_reset.Click += new System.EventHandler(this.rsa_encryptor_reset_Click);
            // 
            // rsa_encryptor_plain_label
            // 
            this.rsa_encryptor_plain_label.AutoSize = true;
            this.rsa_encryptor_plain_label.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_encryptor_plain_label.Location = new System.Drawing.Point(5, 60);
            this.rsa_encryptor_plain_label.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.rsa_encryptor_plain_label.Name = "rsa_encryptor_plain_label";
            this.rsa_encryptor_plain_label.Size = new System.Drawing.Size(281, 46);
            this.rsa_encryptor_plain_label.TabIndex = 12;
            this.rsa_encryptor_plain_label.Text = "Plain Message";
            // 
            // rsa_encryptor_encrypt
            // 
            this.rsa_encryptor_encrypt.BackColor = System.Drawing.SystemColors.ControlDark;
            this.rsa_encryptor_encrypt.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.rsa_encryptor_encrypt.Location = new System.Drawing.Point(2667, 143);
            this.rsa_encryptor_encrypt.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_encryptor_encrypt.Name = "rsa_encryptor_encrypt";
            this.rsa_encryptor_encrypt.Size = new System.Drawing.Size(400, 79);
            this.rsa_encryptor_encrypt.TabIndex = 11;
            this.rsa_encryptor_encrypt.Text = "Encrypt";
            this.rsa_encryptor_encrypt.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.rsa_encryptor_encrypt.UseVisualStyleBackColor = false;
            this.rsa_encryptor_encrypt.Click += new System.EventHandler(this.rsa_encryptor_encrypt_Click);
            // 
            // tabPage10
            // 
            this.tabPage10.BackColor = System.Drawing.SystemColors.ControlLight;
            this.tabPage10.Controls.Add(this.rsa_decryptor_result_group);
            this.tabPage10.Controls.Add(this.rsa_decryptor_input_group);
            this.tabPage10.Location = new System.Drawing.Point(10, 28);
            this.tabPage10.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage10.Name = "tabPage10";
            this.tabPage10.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.tabPage10.Size = new System.Drawing.Size(3137, 1278);
            this.tabPage10.TabIndex = 11;
            this.tabPage10.Text = "RSA Decryptor";
            // 
            // rsa_decryptor_result_group
            // 
            this.rsa_decryptor_result_group.BackColor = System.Drawing.SystemColors.ControlLight;
            this.rsa_decryptor_result_group.Controls.Add(this.rsa_decryptor_result_output);
            this.rsa_decryptor_result_group.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_decryptor_result_group.Location = new System.Drawing.Point(8, 589);
            this.rsa_decryptor_result_group.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_decryptor_result_group.Name = "rsa_decryptor_result_group";
            this.rsa_decryptor_result_group.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_decryptor_result_group.Size = new System.Drawing.Size(3109, 651);
            this.rsa_decryptor_result_group.TabIndex = 16;
            this.rsa_decryptor_result_group.TabStop = false;
            this.rsa_decryptor_result_group.Text = "Result";
            // 
            // rsa_decryptor_result_output
            // 
            this.rsa_decryptor_result_output.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.rsa_decryptor_result_output.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_decryptor_result_output.Location = new System.Drawing.Point(40, 72);
            this.rsa_decryptor_result_output.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_decryptor_result_output.Multiline = true;
            this.rsa_decryptor_result_output.Name = "rsa_decryptor_result_output";
            this.rsa_decryptor_result_output.ReadOnly = true;
            this.rsa_decryptor_result_output.Size = new System.Drawing.Size(2611, 565);
            this.rsa_decryptor_result_output.TabIndex = 28;
            this.rsa_decryptor_result_output.TabStop = false;
            // 
            // rsa_decryptor_input_group
            // 
            this.rsa_decryptor_input_group.Controls.Add(this.rsa_decryptor_enc_input);
            this.rsa_decryptor_input_group.Controls.Add(this.rsa_decryptor_reset);
            this.rsa_decryptor_input_group.Controls.Add(this.rsa_decryptor_enc_label);
            this.rsa_decryptor_input_group.Controls.Add(this.rsa_decryptor_decrypt);
            this.rsa_decryptor_input_group.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_decryptor_input_group.Location = new System.Drawing.Point(8, 14);
            this.rsa_decryptor_input_group.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_decryptor_input_group.Name = "rsa_decryptor_input_group";
            this.rsa_decryptor_input_group.Padding = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_decryptor_input_group.Size = new System.Drawing.Size(3109, 560);
            this.rsa_decryptor_input_group.TabIndex = 15;
            this.rsa_decryptor_input_group.TabStop = false;
            this.rsa_decryptor_input_group.Text = "Input";
            // 
            // rsa_decryptor_enc_input
            // 
            this.rsa_decryptor_enc_input.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_decryptor_enc_input.Location = new System.Drawing.Point(408, 57);
            this.rsa_decryptor_enc_input.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_decryptor_enc_input.Multiline = true;
            this.rsa_decryptor_enc_input.Name = "rsa_decryptor_enc_input";
            this.rsa_decryptor_enc_input.Size = new System.Drawing.Size(2236, 471);
            this.rsa_decryptor_enc_input.TabIndex = 45;
            // 
            // rsa_decryptor_reset
            // 
            this.rsa_decryptor_reset.BackColor = System.Drawing.SystemColors.ControlDark;
            this.rsa_decryptor_reset.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.rsa_decryptor_reset.Location = new System.Drawing.Point(2667, 48);
            this.rsa_decryptor_reset.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_decryptor_reset.Name = "rsa_decryptor_reset";
            this.rsa_decryptor_reset.Size = new System.Drawing.Size(400, 79);
            this.rsa_decryptor_reset.TabIndex = 20;
            this.rsa_decryptor_reset.Text = "Reset";
            this.rsa_decryptor_reset.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.rsa_decryptor_reset.UseVisualStyleBackColor = false;
            this.rsa_decryptor_reset.Click += new System.EventHandler(this.rsa_decryptor_reset_Click);
            // 
            // rsa_decryptor_enc_label
            // 
            this.rsa_decryptor_enc_label.AutoSize = true;
            this.rsa_decryptor_enc_label.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rsa_decryptor_enc_label.Location = new System.Drawing.Point(5, 60);
            this.rsa_decryptor_enc_label.Margin = new System.Windows.Forms.Padding(8, 0, 8, 0);
            this.rsa_decryptor_enc_label.Name = "rsa_decryptor_enc_label";
            this.rsa_decryptor_enc_label.Size = new System.Drawing.Size(372, 46);
            this.rsa_decryptor_enc_label.TabIndex = 12;
            this.rsa_decryptor_enc_label.Text = "Encrypted Message";
            // 
            // rsa_decryptor_decrypt
            // 
            this.rsa_decryptor_decrypt.BackColor = System.Drawing.SystemColors.ControlDark;
            this.rsa_decryptor_decrypt.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.rsa_decryptor_decrypt.Location = new System.Drawing.Point(2667, 143);
            this.rsa_decryptor_decrypt.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.rsa_decryptor_decrypt.Name = "rsa_decryptor_decrypt";
            this.rsa_decryptor_decrypt.Size = new System.Drawing.Size(400, 79);
            this.rsa_decryptor_decrypt.TabIndex = 11;
            this.rsa_decryptor_decrypt.Text = "Decrypt";
            this.rsa_decryptor_decrypt.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.rsa_decryptor_decrypt.UseVisualStyleBackColor = false;
            this.rsa_decryptor_decrypt.Click += new System.EventHandler(this.rsa_decryptor_decrypt_Click);
            // 
            // menuStrip1
            // 
            this.menuStrip1.ImageScalingSize = new System.Drawing.Size(40, 40);
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.aboutToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Padding = new System.Windows.Forms.Padding(16, 5, 0, 5);
            this.menuStrip1.Size = new System.Drawing.Size(3157, 55);
            this.menuStrip1.TabIndex = 1;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.aboutToolStripMenuItem1,
            this.exitToolStripMenuItem});
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(107, 45);
            this.aboutToolStripMenuItem.Text = "Menu";
            // 
            // aboutToolStripMenuItem1
            // 
            this.aboutToolStripMenuItem1.Name = "aboutToolStripMenuItem1";
            this.aboutToolStripMenuItem1.Size = new System.Drawing.Size(214, 46);
            this.aboutToolStripMenuItem1.Text = "About";
            this.aboutToolStripMenuItem1.Click += new System.EventHandler(this.aboutToolStripMenuItem1_Click);
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(214, 46);
            this.exitToolStripMenuItem.Text = "Exit";
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.exitToolStripMenuItem_Click);
            // 
            // groupBox7
            // 
            this.groupBox7.Controls.Add(this.textBox1);
            this.groupBox7.Controls.Add(this.label12);
            this.groupBox7.Controls.Add(this.textBox2);
            this.groupBox7.Controls.Add(this.label13);
            this.groupBox7.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox7.Location = new System.Drawing.Point(8, 177);
            this.groupBox7.Name = "groupBox7";
            this.groupBox7.Size = new System.Drawing.Size(777, 214);
            this.groupBox7.TabIndex = 7;
            this.groupBox7.TabStop = false;
            this.groupBox7.Text = "Result";
            // 
            // textBox1
            // 
            this.textBox1.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox1.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.textBox1.Location = new System.Drawing.Point(12, 66);
            this.textBox1.Margin = new System.Windows.Forms.Padding(0);
            this.textBox1.Multiline = true;
            this.textBox1.Name = "textBox1";
            this.textBox1.ReadOnly = true;
            this.textBox1.Size = new System.Drawing.Size(759, 65);
            this.textBox1.TabIndex = 3;
            this.textBox1.TabStop = false;
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Location = new System.Drawing.Point(7, 37);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(454, 61);
            this.label12.TabIndex = 2;
            this.label12.Text = "Hashed Password";
            // 
            // textBox2
            // 
            this.textBox2.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.textBox2.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.textBox2.Location = new System.Drawing.Point(12, 160);
            this.textBox2.Multiline = true;
            this.textBox2.Name = "textBox2";
            this.textBox2.ReadOnly = true;
            this.textBox2.Size = new System.Drawing.Size(759, 23);
            this.textBox2.TabIndex = 1;
            this.textBox2.TabStop = false;
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Location = new System.Drawing.Point(7, 131);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(511, 61);
            this.label13.TabIndex = 0;
            this.label13.Text = "Encrypted Password";
            // 
            // groupBox8
            // 
            this.groupBox8.Controls.Add(this.button1);
            this.groupBox8.Controls.Add(this.radioButton1);
            this.groupBox8.Controls.Add(this.radioButton2);
            this.groupBox8.Controls.Add(this.radioButton3);
            this.groupBox8.Controls.Add(this.label14);
            this.groupBox8.Controls.Add(this.textBox3);
            this.groupBox8.Controls.Add(this.label15);
            this.groupBox8.Controls.Add(this.button2);
            this.groupBox8.Font = new System.Drawing.Font("Microsoft Sans Serif", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox8.Location = new System.Drawing.Point(7, 8);
            this.groupBox8.Name = "groupBox8";
            this.groupBox8.Size = new System.Drawing.Size(778, 162);
            this.groupBox8.TabIndex = 6;
            this.groupBox8.TabStop = false;
            this.groupBox8.Text = "Input";
            // 
            // button1
            // 
            this.button1.BackColor = System.Drawing.SystemColors.ControlDark;
            this.button1.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.button1.Location = new System.Drawing.Point(622, 84);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(150, 33);
            this.button1.TabIndex = 20;
            this.button1.Text = "Reset";
            this.button1.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.button1.UseVisualStyleBackColor = false;
            // 
            // radioButton1
            // 
            this.radioButton1.AutoSize = true;
            this.radioButton1.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.radioButton1.Location = new System.Drawing.Point(329, 68);
            this.radioButton1.Name = "radioButton1";
            this.radioButton1.Size = new System.Drawing.Size(206, 50);
            this.radioButton1.TabIndex = 19;
            this.radioButton1.TabStop = true;
            this.radioButton1.Text = "SHA512";
            this.radioButton1.UseVisualStyleBackColor = true;
            // 
            // radioButton2
            // 
            this.radioButton2.AutoSize = true;
            this.radioButton2.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.radioButton2.Location = new System.Drawing.Point(223, 68);
            this.radioButton2.Name = "radioButton2";
            this.radioButton2.Size = new System.Drawing.Size(206, 50);
            this.radioButton2.TabIndex = 18;
            this.radioButton2.TabStop = true;
            this.radioButton2.Text = "SHA256";
            this.radioButton2.UseVisualStyleBackColor = true;
            // 
            // radioButton3
            // 
            this.radioButton3.AutoSize = true;
            this.radioButton3.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.radioButton3.Location = new System.Drawing.Point(131, 69);
            this.radioButton3.Name = "radioButton3";
            this.radioButton3.Size = new System.Drawing.Size(162, 50);
            this.radioButton3.TabIndex = 17;
            this.radioButton3.TabStop = true;
            this.radioButton3.Text = "SHA1";
            this.radioButton3.UseVisualStyleBackColor = true;
            // 
            // label14
            // 
            this.label14.AutoSize = true;
            this.label14.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label14.Location = new System.Drawing.Point(3, 70);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(293, 46);
            this.label14.TabIndex = 16;
            this.label14.Text = "Hash Algorithm";
            // 
            // textBox3
            // 
            this.textBox3.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.textBox3.Location = new System.Drawing.Point(131, 28);
            this.textBox3.Name = "textBox3";
            this.textBox3.Size = new System.Drawing.Size(361, 53);
            this.textBox3.TabIndex = 15;
            // 
            // label15
            // 
            this.label15.AutoSize = true;
            this.label15.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label15.Location = new System.Drawing.Point(3, 34);
            this.label15.Name = "label15";
            this.label15.Size = new System.Drawing.Size(296, 46);
            this.label15.TabIndex = 12;
            this.label15.Text = "Plain Password";
            // 
            // button2
            // 
            this.button2.BackColor = System.Drawing.SystemColors.ControlDark;
            this.button2.BackgroundImageLayout = System.Windows.Forms.ImageLayout.Center;
            this.button2.Location = new System.Drawing.Point(622, 123);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(150, 33);
            this.button2.TabIndex = 11;
            this.button2.Text = "Generate";
            this.button2.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageAboveText;
            this.button2.UseVisualStyleBackColor = false;
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // rsa_encryptor_dropdown
            // 
            this.rsa_encryptor_dropdown.DropDownWidth = 500;
            this.rsa_encryptor_dropdown.FormattingEnabled = true;
            this.rsa_encryptor_dropdown.Items.AddRange(new object[] {
            "D+UserAccount",
            "D+Distribution",
            "D+DistributionStatus",
            "D+CampaignReward",
            "D+CampaignRewardStatus",
            "D+PaymentSubmit"});
            this.rsa_encryptor_dropdown.Location = new System.Drawing.Point(2667, 320);
            this.rsa_encryptor_dropdown.Name = "rsa_encryptor_dropdown";
            this.rsa_encryptor_dropdown.Size = new System.Drawing.Size(400, 62);
            this.rsa_encryptor_dropdown.TabIndex = 47;
            this.rsa_encryptor_dropdown.Text = "-- Choose json format Api --";
            this.rsa_encryptor_dropdown.SelectedIndexChanged += new System.EventHandler(this.rsa_encryptor_dropdown_SelectedIndexChanged);
            // 
            // SecurityForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(16F, 31F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.BackColor = System.Drawing.SystemColors.ControlLight;
            this.ClientSize = new System.Drawing.Size(3157, 1385);
            this.Controls.Add(this.tabControl1);
            this.Controls.Add(this.menuStrip1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Margin = new System.Windows.Forms.Padding(8, 7, 8, 7);
            this.Name = "SecurityForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Security Application";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.tabPage2.ResumeLayout(false);
            this.groupBox4.ResumeLayout(false);
            this.groupBox4.PerformLayout();
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.tabPage3.ResumeLayout(false);
            this.groupBox6.ResumeLayout(false);
            this.groupBox6.PerformLayout();
            this.groupBox5.ResumeLayout(false);
            this.groupBox5.PerformLayout();
            this.Pass.ResumeLayout(false);
            this.groupBox9.ResumeLayout(false);
            this.groupBox9.PerformLayout();
            this.groupBox10.ResumeLayout(false);
            this.groupBox10.PerformLayout();
            this.tabPage4.ResumeLayout(false);
            this.groupBox11.ResumeLayout(false);
            this.groupBox11.PerformLayout();
            this.groupBox12.ResumeLayout(false);
            this.groupBox12.PerformLayout();
            this.tabPage5.ResumeLayout(false);
            this.groupBox14.ResumeLayout(false);
            this.groupBox14.PerformLayout();
            this.groupBox13.ResumeLayout(false);
            this.groupBox13.PerformLayout();
            this.tabPage6.ResumeLayout(false);
            this.groupBox15.ResumeLayout(false);
            this.groupBox15.PerformLayout();
            this.groupBox16.ResumeLayout(false);
            this.groupBox16.PerformLayout();
            this.tabPage7.ResumeLayout(false);
            this.groupBox17.ResumeLayout(false);
            this.groupBox17.PerformLayout();
            this.groupBox18.ResumeLayout(false);
            this.groupBox18.PerformLayout();
            this.PlainTextEncrypt.ResumeLayout(false);
            this.groupBox19.ResumeLayout(false);
            this.groupBox19.PerformLayout();
            this.groupBox20.ResumeLayout(false);
            this.groupBox20.PerformLayout();
            this.tabPage8.ResumeLayout(false);
            this.groupBox21.ResumeLayout(false);
            this.groupBox21.PerformLayout();
            this.groupBox22.ResumeLayout(false);
            this.groupBox22.PerformLayout();
            this.tabPage9.ResumeLayout(false);
            this.rsa_encryptor_result_group.ResumeLayout(false);
            this.rsa_encryptor_result_group.PerformLayout();
            this.rsa_encryptor_input_group.ResumeLayout(false);
            this.rsa_encryptor_input_group.PerformLayout();
            this.tabPage10.ResumeLayout(false);
            this.rsa_decryptor_result_group.ResumeLayout(false);
            this.rsa_decryptor_result_group.PerformLayout();
            this.rsa_decryptor_input_group.ResumeLayout(false);
            this.rsa_decryptor_input_group.PerformLayout();
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.groupBox7.ResumeLayout(false);
            this.groupBox7.PerformLayout();
            this.groupBox8.ResumeLayout(false);
            this.groupBox8.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox plainPassword;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.RadioButton SHA512Button;
        private System.Windows.Forms.RadioButton SHA256Button;
        private System.Windows.Forms.RadioButton SHA1Button;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox SaltPrefixInput;
        private System.Windows.Forms.RadioButton SaltPrefixButton;
        private System.Windows.Forms.RadioButton SaltRandomButton;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem exitToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem1;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.Button GeneratePassword;
        private System.Windows.Forms.Label PasswordResultLabel;
        private System.Windows.Forms.TextBox SaltResult;
        private System.Windows.Forms.TextBox PasswordResult;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.GroupBox groupBox3;
        private System.Windows.Forms.Button GenerateSignature;
        private System.Windows.Forms.GroupBox groupBox4;
        private System.Windows.Forms.TextBox SignInputText3;
        private System.Windows.Forms.TextBox SignInputText2;
        private System.Windows.Forms.TextBox SignInputText1;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TabPage tabPage3;
        private System.Windows.Forms.GroupBox groupBox6;
        private System.Windows.Forms.TextBox HashedResultPassword;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.TextBox EncryptedResultPassword;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.GroupBox groupBox5;
        private System.Windows.Forms.RadioButton EN_SHA512Button;
        private System.Windows.Forms.RadioButton EN_SHA256Button;
        private System.Windows.Forms.RadioButton EN_SHA1Button;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.TextBox PasswordToEncrypt;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.Button PasswordEncryptor;
        private System.Windows.Forms.Button ResetPasswordGenerator;
        private System.Windows.Forms.Button ResetSignatureGenerator;
        private System.Windows.Forms.Button ResetPasswordEncryptor;
        private System.Windows.Forms.TextBox SignatureResult;
        private System.Windows.Forms.TabPage Pass;
        private System.Windows.Forms.GroupBox groupBox7;
        private System.Windows.Forms.TextBox textBox1;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.TextBox textBox2;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.GroupBox groupBox8;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.RadioButton radioButton1;
        private System.Windows.Forms.RadioButton radioButton2;
        private System.Windows.Forms.RadioButton radioButton3;
        private System.Windows.Forms.Label label14;
        private System.Windows.Forms.TextBox textBox3;
        private System.Windows.Forms.Label label15;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.GroupBox groupBox9;
        private System.Windows.Forms.TextBox DecipherPassword;
        private System.Windows.Forms.Label label17;
        private System.Windows.Forms.GroupBox groupBox10;
        private System.Windows.Forms.Button PasswordDecryptorReset;
        private System.Windows.Forms.TextBox CipherPassword;
        private System.Windows.Forms.Label label19;
        private System.Windows.Forms.Button PasswordDecrptorGenerate;
        private System.Windows.Forms.TabPage tabPage4;
        private System.Windows.Forms.GroupBox groupBox11;
        private System.Windows.Forms.TextBox SignVerifiedResult;
        private System.Windows.Forms.GroupBox groupBox12;
        private System.Windows.Forms.Button ResetVerify;
        private System.Windows.Forms.TextBox VerifyField3;
        private System.Windows.Forms.TextBox VerifyField2;
        private System.Windows.Forms.TextBox VerifyField1;
        private System.Windows.Forms.Label label16;
        private System.Windows.Forms.Label label18;
        private System.Windows.Forms.Label label20;
        private System.Windows.Forms.Button SignVerify;
        private System.Windows.Forms.TextBox VerifyFieldSign;
        private System.Windows.Forms.Label label21;
        private System.Windows.Forms.CheckBox Field2Checked;
        private System.Windows.Forms.CheckBox Field1Checked;
        private System.Windows.Forms.CheckBox SG_EN_F2;
        private System.Windows.Forms.CheckBox SG_EN_F1;
        private System.Windows.Forms.TabPage tabPage5;
        private System.Windows.Forms.GroupBox groupBox13;
        private System.Windows.Forms.Button resetSecret;
        private System.Windows.Forms.Button generateSecret;
        private System.Windows.Forms.TextBox secretmsgbox;
        private System.Windows.Forms.Label label25;
        private System.Windows.Forms.GroupBox groupBox14;
        private System.Windows.Forms.TextBox secretkey64box;
        private System.Windows.Forms.Label label22;
        private System.Windows.Forms.TextBox FileOutputExportSecretKey;
        private System.Windows.Forms.Label label23;
        private System.Windows.Forms.Button exportSecret;
        private System.Windows.Forms.RadioButton SK_SHA512;
        private System.Windows.Forms.RadioButton SK_SHA256;
        private System.Windows.Forms.Label label24;
        private System.Windows.Forms.TabPage tabPage6;
        private System.Windows.Forms.TabPage tabPage7;
        private System.Windows.Forms.GroupBox groupBox15;
        private System.Windows.Forms.GroupBox groupBox16;
        private System.Windows.Forms.RadioButton hmac_gen_sha512;
        private System.Windows.Forms.RadioButton hmac_gen_sha256;
        private System.Windows.Forms.Label label28;
        private System.Windows.Forms.Button hmac_gen_reset;
        private System.Windows.Forms.Button hmac_gen_generator;
        private System.Windows.Forms.TextBox hmac_gen_msg;
        private System.Windows.Forms.Label label29;
        private System.Windows.Forms.GroupBox groupBox17;
        private System.Windows.Forms.TextBox hmac_ver_signresult;
        private System.Windows.Forms.GroupBox groupBox18;
        private System.Windows.Forms.Button hmac_ver_reset;
        private System.Windows.Forms.Button hmac_ver_generator;
        private System.Windows.Forms.CheckBox hmac_gen_defsk;
        private System.Windows.Forms.TextBox hmac_gen_sk;
        private System.Windows.Forms.Label label30;
        private System.Windows.Forms.TextBox hmac_ver_signature;
        private System.Windows.Forms.Label label34;
        private System.Windows.Forms.CheckBox hmac_ver_defsk;
        private System.Windows.Forms.TextBox hmac_ver_sk;
        private System.Windows.Forms.Label label26;
        private System.Windows.Forms.RadioButton hmac_ver_sha512;
        private System.Windows.Forms.RadioButton hmac_ver_sha256;
        private System.Windows.Forms.Label label32;
        private System.Windows.Forms.TextBox hmac_ver_msg;
        private System.Windows.Forms.Label label33;
        private System.Windows.Forms.Label label31;
        private System.Windows.Forms.TextBox hmac_gen_signaturehexbinary;
        private System.Windows.Forms.TabPage PlainTextEncrypt;
        private System.Windows.Forms.GroupBox groupBox19;
        private System.Windows.Forms.TextBox plainText_enc_result;
        private System.Windows.Forms.GroupBox groupBox20;
        private System.Windows.Forms.TextBox plainText_enc_sk_input;
        private System.Windows.Forms.Label label35;
        private System.Windows.Forms.Button plainText_enc_reset;
        private System.Windows.Forms.Label label37;
        private System.Windows.Forms.TabPage tabPage8;
        private System.Windows.Forms.GroupBox groupBox21;
        private System.Windows.Forms.TextBox plainText_dec_result;
        private System.Windows.Forms.GroupBox groupBox22;
        private System.Windows.Forms.TextBox plainText_dec_sk_input;
        private System.Windows.Forms.Label label38;
        private System.Windows.Forms.Button plainText_dec_reset;
        private System.Windows.Forms.CheckBox plainText_enc_defkey;
        private System.Windows.Forms.CheckBox plainText_dec_defkey;
        private System.Windows.Forms.Button plainText_enc_upload;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Label label39;
        private System.Windows.Forms.TextBox plainText_dec_msg_input;
        private System.Windows.Forms.Button plainText_dec_generator;
        private System.Windows.Forms.Button plainText_enc_generator;
        private System.Windows.Forms.CheckBox plainText_enc_allow_fileinput;
        private System.Windows.Forms.TextBox plainText_enc_msg_input;
        private System.Windows.Forms.CheckBox plainText_dec_allow_fileinput;
        private System.Windows.Forms.Button plainText_dec_upload;
        private System.Windows.Forms.TabPage tabPage9;
        private System.Windows.Forms.TabPage tabPage10;
        private System.Windows.Forms.Label label27;
        private System.Windows.Forms.GroupBox rsa_encryptor_input_group;
        private System.Windows.Forms.Button rsa_encryptor_reset;
        private System.Windows.Forms.Label rsa_encryptor_plain_label;
        private System.Windows.Forms.Button rsa_encryptor_encrypt;
        private System.Windows.Forms.GroupBox rsa_encryptor_result_group;
        private System.Windows.Forms.TextBox rsa_encryptor_result_output;
        private System.Windows.Forms.TextBox rsa_encryptor_plain_input;
        private System.Windows.Forms.GroupBox rsa_decryptor_result_group;
        private System.Windows.Forms.TextBox rsa_decryptor_result_output;
        private System.Windows.Forms.GroupBox rsa_decryptor_input_group;
        private System.Windows.Forms.TextBox rsa_decryptor_enc_input;
        private System.Windows.Forms.Button rsa_decryptor_reset;
        private System.Windows.Forms.Label rsa_decryptor_enc_label;
        private System.Windows.Forms.Button rsa_decryptor_decrypt;
        private System.Windows.Forms.CheckBox allowed_Encoded;
        private System.Windows.Forms.CheckBox plainText_enc_ggit_wallet_library_setting;
        private System.Windows.Forms.CheckBox plainText_dec_ggit_wallet_library_setting;
        private System.Windows.Forms.ComboBox rsa_encryptor_dropdown;
    }
}

