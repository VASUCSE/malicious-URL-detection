import java.util.Scanner;
class hello {
    public static void main  (String args[]) {
        Scanner bhuvi = new Scanner(System.in);
        System.out.println("Enter your mark :");
        int num = bhuvi.nextInt();
        if(num>=90)
            System.out.println("Grade A");
        else if(num>=80)
            System.out.println("Grade B");
        else if(num>=70)
            System.out.println("Grade C");
        else if(num>=60)
            System.out.println("Grade D");
        else if(num>=50)
            System.out.println("Grade E");
        else
            System.out.println("Fail");
    }
}