<?php

   
Class Model_test extends Model
{

    function __construct()
    {    
        // Call the Model constructor
        parent::__construct();
        
        // Load database connection
        
         ### WARNING database i burada ilan edince çalışmıyo !! ###
        //load another model 
        //loader::model('blog/model_blog');
        
        loader::database();
        
        // Using library from model
        loader::library('myclass');
    }

    /**
    * Test Function
    * @link http://tr.php.net/manual/en/pdostatement.fetch.php  
    */
    public function test()
    {   
        //ob::input_set('name','mahmut');
        //echo ob::input_get('name');
        
        //ob_user::nav_level1();
        
        //echo 'Using Model inside another model: succesfull!<br /> ';
        //$this->model_blog->test();
        
        echo '<b>Using library from model_test:</b> successful!<br /><br /><br />';
        echo '<b>Using database from library:</b> successful!<br /><br /><br />';
        $this->myclass->testDB();
        
        /*---------- Prepared Query ----------*/
        
        echo '<br /><b>Prepared Query:</b><br />';
        
        $this->db->prepare();   // tell to db class use pdo prepare
        $this->db->query("SELECT * FROM articles WHERE article_id=:id OR link=:code");
        $this->db->bval(':id', $id=1, p_int); //INTEGER 
        // alias of PDOStatement::bindValue();
        
        $this->db->bval(':code',$code='i-see-dead-people', p_str);
         
        //STRING // alias PDOStatement::bindValue();  
        //$this->db->param(':colour', $colour, PDO::PARAM_STR); 
        //alias of pdo::bindParam() 
        
        $this->db->exec();
        $a = $this->db->all(assoc);  // or obj
        print_r($a);
        
        $this->db->exec();
        $a = $this->db->row();  // or obj
        echo '<br />'.$a->title;
        
        /*---------- Prepared Query ----------*/
        
        /*------- Without bindvalue ----------*/
        
        echo '<br /><br /><b>Without bindvalue Query:</b> <br />';
                    
        $this->db->prepare();   // tell to db class use pdo prepare
        $this->db->query("SELECT * FROM articles WHERE article_id=:id"); 

        $this->db->exec(array(':id'=>1));           
        $a = $this->db->assoc();
        print_r($a).'<br />';
        
        // change the value
        $this->db->exec(array(':id'=>2));
        $b = $this->db->row();   
        echo '<br />'.$b->article;
        
        /*------- Without bindvalue ----------*/
        
        
        /*-- Direct Query and Next Row Example --*/
        
        echo '<br /><br /><b>Direct Query:</b> <br />';
        
        $res = $this->db->query("SELECT * FROM articles");
        
        $a = $res->num_rows();  
        echo $a.'<br /><br />';
        
        $b = $res->assoc();     // NEXT ROW
        print_r($b).'<br />';
        
        $c = $res->obj(); //object  // NEXT ROW
        echo $c->article.'<br /><br />';
        
        $d = $res->all(assoc); //or obj // NEXT ROW
        '<br />'.print_r($d).'<br /><br />'; 
        
        /*-- Direct Query and Next Row Example --*/

        
    } //end func.

} //end class



?>
