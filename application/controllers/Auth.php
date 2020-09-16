<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends CI_Controller
{

    public function __construct()
    {
        parent::__construct();

        $this->load->library('form_validation');
        $this->load->helper('captcha');
    }

    public function index()
    {
        $this->form_validation->set_rules('email', 'Email', 'trim|required|valid_email');
        $this->form_validation->set_rules('password', 'Password', 'trim|required');
        $this->form_validation->set_rules('captcha', 'captcha', 'trim|required');
        
        if ($this->form_validation->run() == false) {
            $randomWord = array_merge(range('0','9'));
            $shuffle = shuffle($randomWord);
            $str = substr(implode($randomWord), 0,5);

            $data_ses = array('captcha_str'=>$str);
            $this->session->set_userdata($data_ses);
            
            $option = [

                'word' => $str,
                'img_path' => './captcha/',
                'img_url' => base_url() . 'captcha',
                'img_width' => '180',
                'img_height' => '50',
                'expiration' => 7200
            ];
            $cap = create_captcha($option);
            $data['captcha_image'] = $cap['image'];

            $data['title'] = 'App dek Login';
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/login', $data);
            $this->load->view('templates/auth_footer');
         
        } else {
            //validation
           
            $this->_login();
        }
    }
        

    private function _login()
    {
        //parse data form to database
        $email = $this->input->post('email');
        $password = $this->input->post('password');
        //query database where email exist or no
        $user = $this->db->get_where('user', ['email' => $email])->row_array();
        //if user registered
        if ($user) {
            //if user active
            if ($user['is_active'] == 1) {
                //check password if (password_verify($password, $user['password']))
                if (password_verify($password, $user['password'])) {
                    $data = [
                        'email' => $user['email'],
                        'role_id' => $user['role_id']
                    ];
                 
                    //from input captcha
                    $post_captcha = $this->input->post('captcha');

                    //from image captcha
                    $session_captcha = $this->session->userdata('captcha_str');
                    
                    //check captcha true or not

                    if ($post_captcha == $session_captcha) {
                        
                        $this->session->set_userdata($data);
                        redirect('user');

                    }else {
                        
                        $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert"> 
                        Wrong captcha </div>');
                        redirect('auth');
                    }
                } else {
                    $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert"> 
                    Wrong password </div>');
                    redirect('auth');
                }
            } else {
                $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert"> 
            This email has not been activated! </div>');
                redirect('auth');
            }
        } else {
            $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert"> 
            Email is not registered </div>');
            redirect('auth');
        }
    }

    public function register()
    {
        $this->form_validation->set_rules('name', 'Name', 'required|trim');
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[user.email]', [
            'is_unique' => 'This email has already register!'
        ]);
        $this->form_validation->set_rules('password1', 'Password', 'required|trim|min_length[6]|matches[password2]', [
            'matches' => 'password not match!',
            'min_length' => 'password to short'
        ]);
        $this->form_validation->set_rules('password2', 'Password', 'required|trim|matches[password1]');
        if ($this->form_validation->run() == false) {

            $data['title'] = 'App dek register';
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/register');
            $this->load->view('templates/auth_footer');
        } else {


            $data = [
                'name' => $this->input->post('name', true),
                'email' => $this->input->post('email', true),
                'image' => 'default.jpg',
                'password' => password_hash($this->input->post('password1'), PASSWORD_DEFAULT),
                // 'password' => base64_encode($this->input->post['password1']),
                'role_id' => 2,
                'is_active' => 1,
                'date_created' => time()

            ];

            $this->db->insert('user', $data);
            $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert"> 
            Congratulation! your account has been created. 
            Please Activated check your email!</div>');
            redirect('auth');
        }
    }

    public function logout()
    {
        $this->session->unset_userdata('email');
        $this->session->unset_userdata('role_id');
        $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert"> 
            You have been logout!</div>');
        redirect('auth');
    }
}
